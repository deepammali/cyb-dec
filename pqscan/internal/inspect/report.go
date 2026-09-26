package inspect

import (
	"fmt"
	"sort"
	"strings"

	"pqscan/internal/report"
)

// Report is the result of inspecting a set of files.
type Report struct {
	Roots           []string                `json:"roots"`
	Files           int                     `json:"files"` // files, archive members, and mail parts examined
	Bytes           int64                   `json:"bytes"`
	Findings        []Finding               `json:"findings"`
	Counts          map[Class]int           `json:"counts"`
	Verdict         report.Verdict          `json:"verdict"`
	Headline        string                  `json:"headline"`
	Recommendations []report.Recommendation `json:"recommendations"`
	Skipped         []Skip                  `json:"skipped,omitempty"`
	SkippedTotal    int                     `json:"skippedTotal,omitempty"`
	Partial         bool                    `json:"partial,omitempty"` // stopped before everything was read
}

var classRank = func() map[Class]int {
	m := map[Class]int{}
	for i, c := range ClassOrder {
		m[c] = i
	}
	return m
}()

// Report summarizes what the inspector found so far.
func (in *Inspector) Report() Report {
	r := Report{Roots: in.roots, Files: in.files, Bytes: in.bytes, Skipped: in.skipped, SkippedTotal: in.skips, Partial: in.ctx.Err() != nil}
	r.Findings = append([]Finding{}, in.findings...)
	sort.SliceStable(r.Findings, func(i, j int) bool { return classRank[r.Findings[i].Class] < classRank[r.Findings[j].Class] })
	return Summarize(r)
}

// Summarize fills in counts, verdict, headline, and recommendations.
func Summarize(r Report) Report {
	r.Counts = map[Class]int{}
	for _, f := range r.Findings {
		r.Counts[f.Class]++
	}
	c := r.Counts
	n := len(r.Findings)
	switch {
	case n == 0:
		r.Verdict = report.Undetermined
		r.Headline = fmt.Sprintf("No encrypted data, keys, or certificates found in %d %s.", r.Files, plural(r.Files, "file", "files"))
	case c[ClassExposed] > 0:
		r.Verdict = report.NotReady
		r.Headline = fmt.Sprintf("%d of %d %s encrypted to classical public keys: exposed to harvest-now-decrypt-later.", c[ClassExposed], n, plural(n, "artifact is", "artifacts are"))
		if c[ClassExposed] == 1 {
			r.Headline = fmt.Sprintf("1 of %d %s encrypted to a classical public key: exposed to harvest-now-decrypt-later.", n, plural(n, "artifact is", "artifacts is"))
		}
	case c[ClassWeak] > 0:
		r.Verdict = report.NotReady
		r.Headline = fmt.Sprintf("%d %s weak protection today, before any quantum computer.", c[ClassWeak], plural(c[ClassWeak], "artifact uses", "artifacts use"))
	default:
		r.Verdict = report.Ready
		r.Headline = "Nothing here is exposed to harvest-now-decrypt-later: encrypted data is post-quantum or symmetric-only."
		if c[ClassSymmetric]+c[ClassPQ] == 0 {
			r.Headline = "No encrypted data found; only keys and certificates."
		}
	}
	if r.Verdict == report.NotReady && c[ClassWeak] > 0 && c[ClassExposed] > 0 {
		r.Headline = strings.TrimSuffix(r.Headline, ".") + fmt.Sprintf("; %d %s weak protection.", c[ClassWeak], plural(c[ClassWeak], "uses", "use"))
	}
	if c[ClassInventory] > 0 {
		r.Headline += fmt.Sprintf(" %d classical %s to migrate.", c[ClassInventory], plural(c[ClassInventory], "key or certificate", "keys and certificates"))
	}
	r.Recommendations = Recommend(r.Findings)
	return r
}

var (
	refRFC9980 = report.Ref{Label: "RFC 9980 (PQC in OpenPGP)", URL: "https://www.rfc-editor.org/rfc/rfc9980"}
	refAge     = report.Ref{Label: "age v1 specification", URL: "https://c2sp.org/age"}
	refRFC9629 = report.Ref{Label: "RFC 9629 (KEMRecipientInfo)", URL: "https://www.rfc-editor.org/rfc/rfc9629"}
	refFIPS203 = report.Ref{Label: "FIPS 203 (ML-KEM)", URL: "https://doi.org/10.6028/NIST.FIPS.203"}
	refFIPS204 = report.Ref{Label: "FIPS 204 (ML-DSA)", URL: "https://doi.org/10.6028/NIST.FIPS.204"}
)

// Recommend derives actions from the findings' flags. Services lists the
// affected paths.
func Recommend(fs []Finding) []report.Recommendation {
	paths := func(match func(Finding) bool) []string {
		var out []string
		for _, f := range fs {
			if match(f) {
				out = append(out, f.Path)
			}
		}
		return uniq(out)
	}
	formats := func(match func(Finding) bool) map[string]bool {
		out := map[string]bool{}
		for _, f := range fs {
			if match(f) {
				out[f.Format] = true
			}
		}
		return out
	}
	hasFormat := func(set map[string]bool, prefix string) bool {
		for k := range set {
			if strings.HasPrefix(k, prefix) {
				return true
			}
		}
		return false
	}
	out := []report.Recommendation{}

	exposed := func(f Finding) bool { return f.Class == ClassExposed }
	if p := paths(exposed); len(p) > 0 {
		set := formats(exposed)
		rec := report.Recommendation{
			ID: "reencrypt-pq", Priority: report.PriorityNow, Services: p,
			Title: "Re-encrypt exposed data to post-quantum or symmetric-only keys",
			Why:   "These artifacts wrap their data key with RSA, ECDH, X25519, or ElGamal. A copy taken today can be opened once a quantum computer breaks that algorithm, however strong the content cipher is.",
			Steps: []string{
				"Decide how long each item must stay secret. Anything that must outlive the arrival of a cryptographically relevant quantum computer comes first.",
				"Re-encrypt to post-quantum recipients (below), or wrap the data key with a symmetric key held in a KMS or HSM (AES-256), which Shor's algorithm doesn't affect.",
				"Remove every recipient that isn't post-quantum: one classical recipient is enough to open the file.",
				"Delete or re-encrypt the old copies, including backups. Copies that were already taken stay exposed, so rotate any secrets inside them that must stay secret.",
			},
			Refs: []report.Ref{refFIPS203},
		}
		if hasFormat(set, "age") || hasFormat(set, "SOPS") {
			rec.Snippets = append(rec.Snippets, report.Snippet{Label: "age 1.3+ (post-quantum hybrid recipient)",
				Code: "age-keygen -pq -o key.txt              # prints an age1pq1... recipient\nage -r age1pq1... -o file.age file     # or: age -R recipients.txt"})
			rec.Refs = append(rec.Refs, refAge)
		}
		if hasFormat(set, "SOPS") {
			rec.Snippets = append(rec.Snippets, report.Snippet{Label: "SOPS: switch recipients, then rotate the data key",
				Code: "# .sops.yaml: replace age1... and pgp entries with age1pq1... recipients or a KMS key\nsops updatekeys secrets.yaml\nsops rotate -i secrets.yaml"})
		}
		if hasFormat(set, "OpenPGP") {
			rec.Steps = append(rec.Steps, "OpenPGP: generate recipient keys with the ML-KEM algorithms of RFC 9980 (ML-KEM-768+X25519) in an implementation that supports them, confirm every reader can decrypt, then re-encrypt.")
			rec.Refs = append(rec.Refs, refRFC9980)
		}
		if hasFormat(set, "CMS") {
			rec.Steps = append(rec.Steps, "S/MIME and CMS: move to KEMRecipientInfo with ML-KEM once your mail clients support it; until then, keep long-lived data in a symmetric-only or post-quantum format instead of mailboxes.")
			rec.Refs = append(rec.Refs, refRFC9629)
		}
		if hasFormat(set, "JWE") {
			rec.Steps = append(rec.Steps, "JWE: for tokens whose claims must stay confidential, use dir or A256KW with a shared key, or a post-quantum key-management algorithm once your JOSE library supports one.")
		}
		out = append(out, rec)
	}

	weak := func(f Finding) bool { return f.has(FlagLegacyCipher) || f.has(FlagNoIntegrity) }
	if p := paths(weak); len(p) > 0 {
		set := formats(weak)
		rec := report.Recommendation{
			ID: "replace-weak", Priority: report.PriorityNow, Services: p,
			Title: "Replace broken or legacy protection",
			Why:   "ZipCrypto, RC2, RC4, DES and 3DES, the JKS key-protection scheme, legacy PEM encryption, and OpenPGP data without integrity protection are attackable today with ordinary computers.",
			Steps: []string{"Re-create each item with a current format and AES-256 (examples below).", "Treat passwords that protected these files as exposed if the files ever left your control."},
		}
		if hasFormat(set, "Encrypted ZIP") {
			rec.Snippets = append(rec.Snippets, report.Snippet{Label: "ZIP with AES-256 (7-Zip)", Code: "7z a -tzip -mem=AES256 -p archive.zip files/"})
		}
		if hasFormat(set, "Java KeyStore") {
			rec.Snippets = append(rec.Snippets, report.Snippet{Label: "JKS → PKCS#12", Code: "keytool -importkeystore -srckeystore store.jks -destkeystore store.p12 -deststoretype pkcs12"})
		}
		if hasFormat(set, "PKCS#12") {
			rec.Snippets = append(rec.Snippets, report.Snippet{Label: "Re-export PKCS#12 with AES-256 (OpenSSL 3)", Code: "openssl pkcs12 -in old.p12 -nodes -legacy -out tmp.pem\nopenssl pkcs12 -export -in tmp.pem -out new.p12 -keypbe AES-256-CBC -certpbe AES-256-CBC\nshred -u tmp.pem"})
		}
		if hasFormat(set, "Encrypted") && (hasFormat(set, "Encrypted RSA") || hasFormat(set, "Encrypted EC") || hasFormat(set, "Encrypted PKCS#8")) {
			rec.Snippets = append(rec.Snippets, report.Snippet{Label: "Private key → PKCS#8 with PBES2/AES-256", Code: "openssl pkcs8 -topk8 -v2 aes-256-cbc -in old.key -out new.key"})
		}
		out = append(out, rec)
	}

	aes128 := func(f Finding) bool { return f.has(FlagAES128) }
	if p := paths(aes128); len(p) > 0 {
		out = append(out, report.Recommendation{
			ID: "aes256-at-rest", Priority: report.PriorityHarden, Services: p,
			Title: "Use 256-bit symmetric keys where CNSA 2.0 applies",
			Why:   "These items use 128-bit keys. Grover's algorithm doesn't make AES-128 practically breakable and NIST still approves it, but CNSA 2.0 (US national-security systems) requires AES-256.",
			Steps: []string{"Where the policy applies, choose AES-256 when re-encrypting (LUKS: --key-size 512 with aes-xts-plain64; OpenPGP: AES-256; JWE: A256GCM)."},
		})
	}

	undeclared := func(f Finding) bool { return f.has(FlagUndeclaredCipher) }
	if p := paths(undeclared); len(p) > 0 {
		out = append(out, report.Recommendation{
			ID: "declared-format", Priority: report.PriorityHarden, Services: p,
			Title:    "Move openssl enc files to a format that records its cryptography",
			Why:      "openssl enc files don't record their cipher or key derivation, so nobody can audit them, and old scripts often used a single MD5 pass to derive the key.",
			Snippets: []report.Snippet{{Label: "age with a passphrase (scrypt)", Code: "age -p -o file.age file"}},
		})
	}

	plain := func(f Finding) bool { return f.has(FlagPlainPrivateKey) }
	if p := paths(plain); len(p) > 0 {
		out = append(out, report.Recommendation{
			ID: "protect-keys", Priority: report.PriorityHarden, Services: p,
			Title: "Protect private keys stored without a passphrase",
			Why:   "Anyone who can read these files holds the keys. This is not a quantum issue, but it undoes every other protection.",
			Steps: []string{"Move keys into a key store, HSM, or agent, or encrypt them with a passphrase (PKCS#8 PBES2 with AES-256; ssh-keygen -p for OpenSSH keys)."},
		})
	}

	encKey := func(f Finding) bool { return f.has(FlagClassicalEncKey) }
	if p := paths(encKey); len(p) > 0 {
		out = append(out, report.Recommendation{
			ID: "replace-enc-keys", Priority: report.PriorityNow, Services: p,
			Title: "Stop encrypting to classical keys",
			Why:   "These are encryption keys and recipients (RSA key transport, ECDH, X25519). Everything encrypted to them from now on is exposed to harvest-now-decrypt-later.",
			Steps: []string{
				"Issue post-quantum replacements: age1pq recipients, OpenPGP ML-KEM-768+X25519 subkeys (RFC 9980), or ML-KEM keys for CMS.",
				"Point encryption tooling and configuration (.sops.yaml, recipient lists, S/MIME certificates) at the new keys.",
				"Keep the old private keys only for decrypting existing data, then re-encrypt that data (see above).",
			},
			Refs: []report.Ref{refFIPS203, refRFC9980, refAge},
		})
	}

	inventory := func(f Finding) bool { return f.has(FlagClassicalKey) && !f.has(FlagClassicalEncKey) }
	if p := paths(inventory); len(p) > 0 {
		out = append(out, report.Recommendation{
			ID: "migrate-signing", Priority: report.PriorityPlan, Services: p,
			Title: "Plan the migration of classical signing keys and certificates",
			Why:   "Signatures only have to hold while they are verified, so they are not a harvest-now-decrypt-later risk. PKI and key rotation take years, and longer RSA or ECC keys don't help against Shor's algorithm.",
			Steps: []string{
				"Keep this list as the inventory: owner, purpose, and expiry for each key and certificate.",
				"Automate issuance and rotation so the switch to ML-DSA (FIPS 204) is a configuration change.",
				"Pilot ML-DSA on an internal CA or code-signing path with OpenSSL 3.5+ or your HSM vendor's release.",
			},
			Refs: []report.Ref{refFIPS204},
		})
	}
	order := map[report.Priority]int{report.PriorityNow: 0, report.PriorityHarden: 1, report.PriorityPlan: 2}
	sort.SliceStable(out, func(i, j int) bool { return order[out[i].Priority] < order[out[j].Priority] })
	return out
}
