package report

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Priority orders recommendations by what is lost by waiting. Traffic recorded
// today can never be re-protected, so HNDL exposure comes first.
type Priority string

const (
	PriorityNow    Priority = "now"    // harvest-now-decrypt-later exposure or plaintext
	PriorityHarden Priority = "harden" // compliance hardening (NIST standardization, CNSA 2.0)
	PriorityPlan   Priority = "plan"   // future work: signature migration, agility
)

// Snippet is a copyable configuration fragment for one product.
type Snippet struct {
	Label string `json:"label"`
	Code  string `json:"code"`
}

// Ref points to the standard or release note behind a recommendation.
type Ref struct {
	Label string `json:"label"`
	URL   string `json:"url"`
}

// Recommendation is one evidence-driven action. Services lists the affected
// services as "Name:port"; every recommendation fires only when a scan result
// triggers it.
type Recommendation struct {
	ID       string    `json:"id"`
	Priority Priority  `json:"priority"`
	Title    string    `json:"title"`
	Why      string    `json:"why"`
	Services []string  `json:"services"`
	Steps    []string  `json:"steps,omitempty"`
	Snippets []Snippet `json:"snippets,omitempty"`
	Refs     []Ref     `json:"refs,omitempty"`
}

var (
	refFIPS203   = Ref{"FIPS 203 (ML-KEM)", "https://doi.org/10.6028/NIST.FIPS.203"}
	refFIPS204   = Ref{"FIPS 204 (ML-DSA)", "https://doi.org/10.6028/NIST.FIPS.204"}
	refTLSMLKEM  = Ref{"draft-ietf-tls-ecdhe-mlkem", "https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/"}
	refRFC8446   = Ref{"RFC 8446 (TLS 1.3)", "https://datatracker.ietf.org/doc/html/rfc8446"}
	refSSHMLKEM  = Ref{"draft-ietf-sshm-mlkem-hybrid-kex", "https://datatracker.ietf.org/doc/draft-ietf-sshm-mlkem-hybrid-kex/"}
	refOpenSSHRN = Ref{"OpenSSH release notes", "https://www.openssh.com/releasenotes.html"}
)

// SvcKey identifies a service in Recommendation.Services.
func SvcKey(s ServiceReport) string { return fmt.Sprintf("%s:%d", s.Service, s.Port) }

func family(s ServiceReport) string {
	if s.Kind == "ssh" {
		return "ssh"
	}
	switch s.Service {
	case "SMTP", "SMTP-submission", "SMTPS":
		return "smtp"
	case "IMAP", "IMAPS", "POP3", "POP3S":
		return "imap"
	case "PostgreSQL":
		return "postgres"
	case "FTP", "FTPS":
		return "ftp"
	}
	return "tls"
}

var opensshRe = regexp.MustCompile(`OpenSSH_(?:for_Windows_)?(\d+)\.(\d+)`)

// opensshVersion extracts major.minor from an SSH identification string.
func opensshVersion(banner string) (major, minor int, ok bool) {
	m := opensshRe.FindStringSubmatch(banner)
	if m == nil {
		return 0, 0, false
	}
	major, _ = strconv.Atoi(m[1])
	minor, _ = strconv.Atoi(m[2])
	return major, minor, true
}

func versionAtLeast(major, minor, wantMajor, wantMinor int) bool {
	return major > wantMajor || (major == wantMajor && minor >= wantMinor)
}

// Recommend derives prioritized recommendations from a host's service reports.
func Recommend(svcs []ServiceReport) []Recommendation {
	var (
		plaintext, tls12, mlkem, legacy        []ServiceReport
		prefer, addX25519, inconsistent        []ServiceReport
		sshOld, sshRestore, sshOther, sshNoMLK []ServiceReport
		cnsaKEM, cnsaAES, certs                []ServiceReport
	)
	for _, s := range svcs {
		switch {
		case isPlaintext(s.ServiceResult):
			plaintext = append(plaintext, s)
		case s.Kind == "ssh" && s.State == StateClassical:
			if maj, min, ok := opensshVersion(s.Banner); !ok {
				sshOther = append(sshOther, s)
			} else if versionAtLeast(maj, min, 9, 0) {
				sshRestore = append(sshRestore, s)
			} else {
				sshOld = append(sshOld, s)
			}
		case s.Kind == "ssh" && s.State == StatePQ:
			if !advertises(s, "mlkem768x25519-sha256") {
				sshNoMLK = append(sshNoMLK, s)
			}
		case s.Kind != "ssh" && s.State == StateClassical:
			switch {
			case supportedNotPreferred(s.ServiceResult):
				prefer = append(prefer, s)
			case s.TLSVersion == "TLS 1.2" || strings.HasPrefix(s.NegotiatedGroup, "none"):
				tls12 = append(tls12, s)
				mlkem = append(mlkem, s)
			case strings.HasSuffix(s.BestPQGroup, "(legacy)"):
				legacy = append(legacy, s)
			default:
				mlkem = append(mlkem, s)
			}
		case s.Kind != "ssh" && s.State == StatePQ:
			switch s.Assessment.Confidence {
			case ConfInconsistent:
				inconsistent = append(inconsistent, s)
			case ConfPartial:
				addX25519 = append(addX25519, s)
			}
			if !supportsGroup(s, "SecP384r1MLKEM1024") && s.Assessment.Confidence != ConfInconsistent {
				cnsaKEM = append(cnsaKEM, s)
			}
		}
		if s.Kind != "ssh" && s.Reachable {
			if s.ServerCipher == "TLS_AES_128_GCM_SHA256" {
				cnsaAES = append(cnsaAES, s)
			}
			if s.CertSigAlg != "" && !strings.Contains(strings.ToUpper(s.CertSigAlg), "ML-DSA") {
				certs = append(certs, s)
			}
		}
	}

	out := []Recommendation{}
	add := func(affected []ServiceReport, r Recommendation) {
		if len(affected) == 0 {
			return
		}
		for _, s := range affected {
			r.Services = append(r.Services, SvcKey(s))
		}
		out = append(out, r)
	}

	// ---- Now: exposure to recording today ----
	add(plaintext, Recommendation{
		ID: "plaintext", Priority: PriorityNow,
		Title: "Turn on TLS where traffic is plaintext",
		Why:   "These services accept connections but refuse to start TLS, so anyone on the network path can read their traffic today. No quantum computer is needed.",
		Steps: []string{
			"Install a certificate and enable STARTTLS (or the implicit-TLS port) on each service listed.",
			"Re-scan. Once TLS works, the ML-KEM recommendation applies to these services too.",
		},
		Snippets: plaintextSnippets(plaintext),
	})
	add(tls12, Recommendation{
		ID: "tls13", Priority: PriorityNow,
		Title: "Enable TLS 1.3",
		Why:   "Hybrid ML-KEM key exchange exists only in TLS 1.3. These services negotiated TLS 1.2, so they cannot offer post-quantum key exchange at all.",
		Steps: []string{
			"Make sure the TLS library supports TLS 1.3 (OpenSSL 1.1.1 or newer; 3.5+ also brings ML-KEM).",
			"Allow TLS 1.3 in the service's configuration, then apply the ML-KEM recommendation below.",
		},
		Snippets: []Snippet{
			{"nginx", "ssl_protocols TLSv1.2 TLSv1.3;"},
			{"Apache httpd", "SSLProtocol -all +TLSv1.2 +TLSv1.3"},
		},
		Refs: []Ref{refRFC8446},
	})
	add(mlkem, Recommendation{
		ID: "mlkem", Priority: PriorityNow,
		Title: "Enable hybrid ML-KEM key exchange (X25519MLKEM768)",
		Why:   "These services chose classical key exchange even though ML-KEM was offered first. Anyone recording this traffic today can decrypt it once a large quantum computer exists.",
		Steps: []string{
			"Terminate TLS with OpenSSL 3.5 or newer, Go 1.24+, BoringSSL, or a load balancer/CDN that supports ML-KEM. OpenSSL 3.5 and Go 1.24 offer X25519MLKEM768 by default.",
			"If the configuration pins a group or curve list, put X25519MLKEM768 first and keep X25519 as a fallback for older clients.",
			"Change it where TLS actually terminates (load balancer, reverse proxy, CDN); a backend setting never reaches clients.",
			"Re-scan to confirm the service now reads Post-quantum.",
		},
		Snippets: mlkemSnippets(mlkem, true),
		Refs:     []Ref{refTLSMLKEM, refFIPS203},
	})
	add(prefer, Recommendation{
		ID: "prefer-mlkem", Priority: PriorityNow,
		Title: "Prefer X25519MLKEM768 over classical groups",
		Why:   "These servers already support X25519MLKEM768 but pick classical X25519 when a client offers both, which every current browser does. Real traffic gets classical key exchange.",
		Steps: []string{
			"Put X25519MLKEM768 first in the server's group list; servers that follow their own order will then choose it.",
			"If the server software lets you, enable server-side group preference.",
			"Re-scan: the offer test should now read post-quantum.",
		},
		Snippets: mlkemSnippets(prefer, false),
		Refs:     []Ref{refTLSMLKEM},
	})
	add(addX25519, Recommendation{
		ID: "add-x25519mlkem768", Priority: PriorityNow,
		Title: "Add X25519MLKEM768 for browsers and most clients",
		Why:   "These servers support ML-KEM only in P-256/P-384 hybrids. Current browsers and TLS libraries offer X25519MLKEM768, so they get classical key exchange here.",
		Steps: []string{
			"Add X25519MLKEM768 to the server's group list, ahead of the classical groups; keep the P-256/P-384 hybrids for FIPS clients.",
		},
		Snippets: mlkemSnippets(addX25519, true),
		Refs:     []Ref{refTLSMLKEM},
	})
	add(inconsistent, Recommendation{
		ID: "inconsistent", Priority: PriorityNow,
		Title: "Check every server behind this address",
		Why:   "The two checks disagreed: the server chose ML-KEM on one connection and refused it on another. That usually means several servers with different TLS settings share this address, so some clients get classical key exchange.",
		Steps: []string{
			"Scan each backend directly by IP, or review the load-balancer pool for servers on an older TLS library or configuration.",
			"Re-scan the shared address; both checks should agree.",
		},
	})
	add(legacy, Recommendation{
		ID: "legacy-kyber", Priority: PriorityNow,
		Title: "Replace the Kyber draft group with X25519MLKEM768",
		Why:   "X25519Kyber768Draft00 was a pre-standard experiment. Current browsers and TLS libraries offer only the final ML-KEM group, so real clients fall back to classical key exchange here.",
		Steps: []string{
			"Upgrade the TLS library to one that implements X25519MLKEM768 (OpenSSL 3.5+, BoringSSL, Go 1.24+).",
			"Remove X25519Kyber768Draft00 from any configured group list and put X25519MLKEM768 first.",
		},
		Refs: []Ref{refTLSMLKEM},
	})
	add(sshOld, Recommendation{
		ID: "ssh-upgrade", Priority: PriorityNow,
		Title: "Upgrade OpenSSH to 9.9 or newer (10.0+ preferred)",
		Why:   "These servers run OpenSSH older than 9.0, which does not use post-quantum key exchange by default. OpenSSH 9.0 made sntrup761x25519 the default, 9.9 added mlkem768x25519-sha256, and 10.0 made ML-KEM the default.",
		Steps: []string{
			"Upgrade through your OS vendor's packages where possible.",
			"Confirm the running server offers a post-quantum method: sshd -T | grep -i kexalgorithms",
			"Re-scan.",
		},
		Refs: []Ref{refOpenSSHRN},
	})
	add(sshRestore, Recommendation{
		ID: "ssh-restore", Priority: PriorityNow,
		Title: "Restore post-quantum key exchange in sshd",
		Why:   "These OpenSSH versions enable post-quantum key exchange by default, so something in the configuration is removing it: a KexAlgorithms line in sshd_config or a system-wide crypto policy.",
		Steps: []string{
			"Find the override: sshd -T | grep -i kexalgorithms",
			"Remove the KexAlgorithms line to return to the defaults, or put the post-quantum methods first as below. On RHEL/Fedora, check the system crypto policy (update-crypto-policies) too.",
			"Reload sshd and re-scan.",
		},
		Snippets: sshKexSnippets(sshRestore),
		Refs:     []Ref{refOpenSSHRN, refSSHMLKEM},
	})
	add(sshOther, Recommendation{
		ID: "ssh-other", Priority: PriorityNow,
		Title: "Enable post-quantum key exchange on the SSH server",
		Why:   "These SSH servers advertise no post-quantum key-exchange method, so sessions recorded today can be decrypted later.",
		Steps: []string{
			"Check whether a newer release supports mlkem768x25519-sha256 (or sntrup761x25519-sha512) and enable it.",
			"If the server has no post-quantum support, plan a replacement for hosts that carry sensitive sessions.",
		},
		Refs: []Ref{refSSHMLKEM},
	})

	// ---- Harden: standards and compliance ----
	add(sshNoMLK, Recommendation{
		ID: "ssh-mlkem", Priority: PriorityHarden,
		Title: "Add mlkem768x25519-sha256 to SSH",
		Why:   "sntrup761x25519 is post-quantum but not NIST-standardized. ML-KEM (FIPS 203) is what compliance frameworks such as CNSA 2.0 expect.",
		Steps: []string{
			"OpenSSH 9.9+ supports mlkem768x25519-sha256 and 10.0 uses it by default; upgrade if older.",
			"If KexAlgorithms is set, add it first:",
		},
		Snippets: []Snippet{{"sshd_config (OpenSSH 9.9+)", "KexAlgorithms mlkem768x25519-sha256,sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org"}},
		Refs:     []Ref{refSSHMLKEM, refFIPS203},
	})
	add(cnsaKEM, Recommendation{
		ID: "cnsa-mlkem1024", Priority: PriorityHarden,
		Title: "Add ML-KEM-1024 where CNSA 2.0 applies",
		Why:   "X25519MLKEM768 already defeats harvest-now-decrypt-later. CNSA 2.0 (US national-security systems) additionally requires ML-KEM-1024; skip this if that policy doesn't apply to you.",
		Snippets: []Snippet{
			{"nginx (OpenSSL 3.5+)", "ssl_ecdh_curve SecP384r1MLKEM1024:X25519MLKEM768:X25519:prime256v1;"},
			{"Apache httpd (OpenSSL 3.5+)", "SSLOpenSSLConfCmd Groups SecP384r1MLKEM1024:X25519MLKEM768:X25519:prime256v1"},
		},
		Refs: []Ref{refTLSMLKEM, refFIPS203},
	})
	add(cnsaAES, Recommendation{
		ID: "cnsa-aes256", Priority: PriorityHarden,
		Title: "Prefer AES-256 where CNSA 2.0 applies",
		Why:   "We offered AES-256 first and the server still chose AES-128. AES-128 remains NIST-approved and Grover's algorithm doesn't make it practically breakable, but CNSA 2.0 requires AES-256.",
		Snippets: []Snippet{
			{"nginx", "ssl_conf_command Ciphersuites TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256;\nssl_prefer_server_ciphers on;"},
			{"Apache httpd", "SSLOpenSSLConfCmd Ciphersuites TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256\nSSLHonorCipherOrder on"},
		},
	})

	// ---- Plan: signatures and agility ----
	add(certs, Recommendation{
		ID: "mldsa", Priority: PriorityPlan,
		Title: "Prepare certificates for ML-DSA",
		Why:   "Certificate signatures only need to resist a quantum attacker at the moment of the handshake, so they are not a harvest-now-decrypt-later risk, but PKI changes take years. Longer RSA or ECC keys don't help: Shor's algorithm breaks every key size.",
		Steps: []string{
			"Automate certificate issuance and renewal (for example with ACME) so switching signature algorithms becomes a configuration change.",
			"Inventory places where certificates or public keys are pinned; they break when the algorithm changes.",
			"Internal CA: pilot ML-DSA (FIPS 204) certificates on a test service with OpenSSL 3.5+.",
			"Public certificates: browsers and public CAs don't accept ML-DSA yet; track your CA's roadmap.",
		},
		Snippets: []Snippet{{"OpenSSL 3.5+ pilot CA", "openssl genpkey -algorithm ML-DSA-65 -out pilot-ca.key\nopenssl req -x509 -new -key pilot-ca.key -subj \"/CN=pq-pilot-ca\" -days 30 -out pilot-ca.pem"}},
		Refs:     []Ref{refFIPS204},
	})
	return out
}

func advertises(s ServiceReport, kex string) bool {
	for _, k := range s.Advertised {
		if k == kex {
			return true
		}
	}
	for _, g := range s.Groups {
		if g.Group == kex && g.Supported {
			return true
		}
	}
	return false
}

func supportsGroup(s ServiceReport, name string) bool {
	for _, g := range s.Groups {
		if g.Group == name && g.Supported {
			return true
		}
	}
	return false
}

func families(svcs []ServiceReport) map[string]bool {
	m := map[string]bool{}
	for _, s := range svcs {
		m[family(s)] = true
	}
	return m
}

func plaintextSnippets(svcs []ServiceReport) []Snippet {
	f := families(svcs)
	var out []Snippet
	if f["smtp"] {
		out = append(out, Snippet{"Postfix (main.cf)", "smtpd_tls_cert_file = /etc/ssl/mail.pem\nsmtpd_tls_key_file = /etc/ssl/mail.key\nsmtpd_tls_security_level = may"})
	}
	if f["imap"] {
		out = append(out, Snippet{"Dovecot 2.4", "ssl = yes\nssl_server_cert_file = /etc/ssl/mail.pem\nssl_server_key_file = /etc/ssl/mail.key"})
	}
	if f["postgres"] {
		out = append(out, Snippet{"PostgreSQL (postgresql.conf)", "ssl = on\nssl_cert_file = 'server.crt'\nssl_key_file = 'server.key'"})
	}
	if f["ftp"] {
		out = append(out, Snippet{"vsftpd", "ssl_enable=YES\nrsa_cert_file=/etc/ssl/ftp.pem\nrsa_private_key_file=/etc/ssl/ftp.key"})
	}
	return out
}

// mlkemSnippets returns group-list settings for the affected services' software.
// withGo adds the Go note, which only helps when enabling ML-KEM: Go ignores the
// order of CurvePreferences, so it can't be used to change preference.
func mlkemSnippets(svcs []ServiceReport, withGo bool) []Snippet {
	f := families(svcs)
	var out []Snippet
	if f["tls"] || f["ftp"] {
		out = append(out,
			Snippet{"nginx (built with OpenSSL 3.5+; check nginx -V)", "ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1;"},
			Snippet{"Apache httpd (OpenSSL 3.5+)", "SSLOpenSSLConfCmd Groups X25519MLKEM768:X25519:prime256v1"},
		)
		if withGo {
			out = append(out, Snippet{"Go 1.24+", "// Leave tls.Config.CurvePreferences nil: X25519MLKEM768 is on by default."})
		}
	}
	if f["smtp"] {
		out = append(out, Snippet{"Postfix (main.cf, OpenSSL 3.5+)", "tls_eecdh_auto_curves = X25519MLKEM768 X25519 prime256v1 secp384r1"})
	}
	if f["imap"] {
		out = append(out, Snippet{"Dovecot (OpenSSL 3.5+)", "ssl_curve_list = X25519MLKEM768:X25519:prime256v1"})
	}
	if f["postgres"] {
		out = append(out, Snippet{"PostgreSQL 18+ (OpenSSL 3.5+)", "ssl_groups = 'X25519MLKEM768:X25519:prime256v1'"})
	}
	return out
}

func sshKexSnippets(svcs []ServiceReport) []Snippet {
	var modern, older bool
	for _, s := range svcs {
		if maj, min, ok := opensshVersion(s.Banner); ok && versionAtLeast(maj, min, 9, 9) {
			modern = true
		} else {
			older = true
		}
	}
	var out []Snippet
	if modern {
		out = append(out, Snippet{"sshd_config (OpenSSH 9.9+)", "KexAlgorithms mlkem768x25519-sha256,sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org"})
	}
	if older {
		out = append(out, Snippet{"sshd_config (OpenSSH 9.0–9.8)", "KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org"})
	}
	return out
}
