package observe

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"pqscan/internal/inspect"
	"pqscan/internal/report"
)

// Class is what a connection's key establishment means for recorded traffic.
type Class string

const (
	ClassPQ        Class = "pq"        // ML-KEM (or another post-quantum method) established the keys
	ClassClassical Class = "classical" // classical key exchange: harvest-now-decrypt-later exposed
	ClassPlaintext Class = "plaintext" // no encryption at all
	ClassUnknown   Class = "unknown"   // the capture doesn't show enough to decide
)

// ClassOrder lists classes from most to least urgent.
var ClassOrder = []Class{ClassPlaintext, ClassClassical, ClassUnknown, ClassPQ}

// Connection is one connection, or a group of identical ones (Count).
type Connection struct {
	Protocol       string            `json:"protocol"`
	Client         string            `json:"client"`
	ClientIP       string            `json:"clientIp"`
	Server         string            `json:"server"`
	ServerName     string            `json:"serverName,omitempty"`
	Class          Class             `json:"class"`
	Outcome        string            `json:"outcome"` // pq, server-classical, client-classical, classical, tls12, static-rsa, plaintext, wireguard, incomplete
	KeyExchange    string            `json:"keyExchange"`
	Offered        string            `json:"offered,omitempty"`
	ClientOffersPQ bool              `json:"clientOffersPQ"`
	Version        string            `json:"version,omitempty"`
	Cipher         string            `json:"cipher,omitempty"`
	Headline       string            `json:"headline"`
	Evidence       []inspect.Fact    `json:"evidence"`
	Limits         string            `json:"limits,omitempty"`
	Decryption     string            `json:"decryption,omitempty"`
	Findings       []inspect.Finding `json:"findings,omitempty"` // artifacts in the application data
	Count          int               `json:"count"`
	First          time.Time         `json:"first"`
	Last           time.Time         `json:"last"`
}

func (c *Connection) fact(label, value string) {
	if value != "" {
		c.Evidence = append(c.Evidence, inspect.Fact{Label: label, Value: value})
	}
}

// Label names a connection group for recommendations and the UI.
func (c Connection) Label() string {
	s := c.Protocol + " " + c.Server
	if c.ServerName != "" {
		s += " (" + c.ServerName + ")"
	}
	return s
}

// KeyLogUse reports what a key log unlocked.
type KeyLogUse struct {
	Sessions     int `json:"sessions"`     // TLS 1.3 sessions in the key log
	TLS12Lines   int `json:"tls12Lines"`   // CLIENT_RANDOM lines, not used
	Decrypted    int `json:"decrypted"`    // connections decrypted
	NotDecrypted int `json:"notDecrypted"` // TLS 1.3 connections that couldn't be
}

// Report is the result of analyzing captures.
type Report struct {
	Captures        int                     `json:"captures"`
	Packets         int                     `json:"packets"`
	First           time.Time               `json:"first"`
	Last            time.Time               `json:"last"`
	Connections     int                     `json:"connections"` // analyzed connections
	Unanalyzed      int                     `json:"unanalyzed"`  // TCP connections without a recognizable handshake or protocol
	Groups          []Connection            `json:"groups"`
	Counts          map[Class]int           `json:"counts"` // connections per class
	Clients         []string                `json:"clientsWithoutPQ,omitempty"`
	Findings        []inspect.Finding       `json:"findings,omitempty"`
	KeyLog          *KeyLogUse              `json:"keylog,omitempty"`
	Verdict         report.Verdict          `json:"verdict"`
	Headline        string                  `json:"headline"`
	Recommendations []report.Recommendation `json:"recommendations"`
}

const maxGroupFindings = 50

func groupKey(c Connection) string {
	return strings.Join([]string{c.Protocol, c.ClientIP, c.Server, c.ServerName, c.Outcome, c.KeyExchange, c.Offered, c.Version}, "|")
}

func summarize(r Report, conns []Connection) Report {
	r.Connections = len(conns)
	r.Counts = map[Class]int{}
	index := map[string]int{}
	clients := map[string]bool{}
	for _, c := range conns {
		r.Counts[c.Class]++
		if c.Outcome == "client-classical" {
			clients[c.ClientIP] = true
		}
		r.Findings = append(r.Findings, c.Findings...)
		k := groupKey(c)
		if i, ok := index[k]; ok {
			g := &r.Groups[i]
			g.Count++
			if c.Last.After(g.Last) {
				g.Last = c.Last
			}
			if c.Decryption == "decrypted" {
				g.Decryption = "decrypted"
			}
			if len(g.Findings) < maxGroupFindings {
				g.Findings = append(g.Findings, c.Findings...)
			}
			continue
		}
		index[k] = len(r.Groups)
		r.Groups = append(r.Groups, c)
	}
	rank := map[Class]int{}
	for i, c := range ClassOrder {
		rank[c] = i
	}
	sort.SliceStable(r.Groups, func(i, j int) bool { return rank[r.Groups[i].Class] < rank[r.Groups[j].Class] })
	for ip := range clients {
		r.Clients = append(r.Clients, ip)
	}
	sort.Strings(r.Clients)

	n, c := r.Connections, r.Counts
	exposedData := 0
	for _, f := range r.Findings {
		if f.Class == inspect.ClassExposed || f.Class == inspect.ClassWeak {
			exposedData++
		}
	}
	switch {
	case n == 0:
		r.Verdict = report.Undetermined
		r.Headline = fmt.Sprintf("No TLS, QUIC, SSH, IKEv2, WireGuard, or plaintext application connections found in %d %s.", r.Packets, plural(r.Packets, "packet", "packets"))
	case c[ClassClassical]+c[ClassPlaintext] > 0:
		r.Verdict = report.NotReady
		r.Headline = fmt.Sprintf("%d of %d %s used classical key exchange", c[ClassClassical], n, plural(n, "connection", "connections"))
		if c[ClassClassical] == 1 {
			r.Headline = fmt.Sprintf("1 of %d %s used classical key exchange", n, plural(n, "connection", "connections"))
		}
		if c[ClassPlaintext] > 0 {
			r.Headline += fmt.Sprintf("; %d %s plaintext", c[ClassPlaintext], plural(c[ClassPlaintext], "was", "were"))
		}
		r.Headline += "."
	case c[ClassPQ] > 0:
		r.Verdict = report.Ready
		r.Headline = fmt.Sprintf("Every connection whose handshake was captured used post-quantum key exchange (%d of %d).", c[ClassPQ], n)
	default:
		r.Verdict = report.Undetermined
		r.Headline = "The capture doesn't show enough of any handshake to decide."
	}
	if len(r.Clients) > 0 {
		r.Headline += fmt.Sprintf(" %d %s never offered ML-KEM.", len(r.Clients), plural(len(r.Clients), "client", "clients"))
	}
	if exposedData > 0 {
		r.Headline += fmt.Sprintf(" %d exposed %s found in the traffic.", exposedData, plural(exposedData, "artifact", "artifacts"))
	}
	r.Recommendations = recommend(r)
	return r
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

var mlkemServerSnippets = []report.Snippet{
	{Label: "nginx (built with OpenSSL 3.5+)", Code: "ssl_protocols TLSv1.2 TLSv1.3;\nssl_ecdh_curve X25519MLKEM768:X25519:prime256v1;"},
	{Label: "Apache httpd (OpenSSL 3.5+)", Code: "SSLOpenSSLConfCmd Groups X25519MLKEM768:X25519:prime256v1"},
	{Label: "Go 1.24+", Code: "// Leave tls.Config.CurvePreferences nil: X25519MLKEM768 is on by default."},
}

func recommend(r Report) []report.Recommendation {
	labels := func(match func(Connection) bool, label func(Connection) string) []string {
		var out []string
		seen := map[string]bool{}
		for _, g := range r.Groups {
			if match(g) {
				if l := label(g); !seen[l] {
					seen[l] = true
					out = append(out, l)
				}
			}
		}
		return out
	}
	byServer := func(g Connection) string { return g.Label() }
	tlsLike := func(g Connection) bool {
		return strings.Contains(g.Protocol, "TLS") || g.Protocol == "QUIC"
	}
	out := []report.Recommendation{}
	if s := labels(func(g Connection) bool { return g.Class == ClassPlaintext }, byServer); len(s) > 0 {
		out = append(out, report.Recommendation{ID: "plaintext", Priority: report.PriorityNow, Services: s,
			Title: "Encrypt the plaintext connections",
			Why:   "These connections carry application data without TLS. Anyone on the path can read it today; quantum computers are beside the point.",
			Steps: []string{"Enable TLS on these services (the implicit-TLS port or STARTTLS), then require it on clients.", "Re-capture: these connections should show a TLS handshake with X25519MLKEM768."}})
	}
	if s := labels(func(g Connection) bool { return g.Outcome == "static-rsa" }, byServer); len(s) > 0 {
		out = append(out, report.Recommendation{ID: "static-rsa", Priority: report.PriorityNow, Services: s,
			Title: "Stop using RSA key transport",
			Why:   "TLS 1.2 RSA key exchange has no forward secrecy: the server's private key decrypts every recorded session, whether it is stolen tomorrow or broken by a quantum computer later.",
			Steps: []string{"Disable TLS_RSA_* cipher suites and enable TLS 1.3 with X25519MLKEM768."}, Snippets: mlkemServerSnippets})
	}
	if s := labels(func(g Connection) bool {
		return tlsLike(g) && (g.Outcome == "server-classical" || g.Outcome == "tls12")
	}, byServer); len(s) > 0 {
		out = append(out, report.Recommendation{ID: "server-mlkem", Priority: report.PriorityNow, Services: s,
			Title:    "Enable ML-KEM on these servers",
			Why:      "Clients reached these servers with classical key exchange, and every such session can be recorded now and decrypted later. Where clients offered ML-KEM, the server alone decided against it.",
			Steps:    []string{"Upgrade the TLS library to one with X25519MLKEM768 (OpenSSL 3.5+, BoringSSL, Go 1.24+) and enable TLS 1.3.", "Put X25519MLKEM768 first in the server's group list.", "If a load balancer or CDN terminates TLS, change it there."},
			Snippets: mlkemServerSnippets})
	}
	if s := labels(func(g Connection) bool { return tlsLike(g) && g.Outcome == "client-classical" }, func(g Connection) string {
		dest := g.ServerName
		if dest == "" {
			dest = g.Server
		}
		return g.ClientIP + " → " + dest
	}); len(s) > 0 {
		out = append(out, report.Recommendation{ID: "client-mlkem", Priority: report.PriorityNow, Services: s,
			Title: "Upgrade clients that never offer ML-KEM",
			Why:   "These clients didn't offer ML-KEM, so no server could have negotiated it with them. A server scan can't see this; only traffic shows it.",
			Steps: []string{"Identify the software behind each client (user agent, service owner) and update its TLS library: OpenSSL 3.5+, Go 1.24+, current Chrome, Edge, and Firefox offer X25519MLKEM768 by default.", "For Java, .NET, and embedded clients, check the vendor's ML-KEM support and the group configuration.", "If a TLS-inspecting proxy sits between clients and servers, it is the client here: upgrade it."}})
	}
	if s := labels(func(g Connection) bool { return g.Protocol == "SSH" && g.Class == ClassClassical }, byServer); len(s) > 0 {
		out = append(out, report.Recommendation{ID: "ssh-pq", Priority: report.PriorityNow, Services: s,
			Title:    "Use post-quantum SSH key exchange",
			Why:      "These SSH sessions used classical key exchange. OpenSSH 9.0+ offers sntrup761x25519-sha512 and 9.9+ offers mlkem768x25519-sha256 by default, so this usually means an old version or an override on one side.",
			Steps:    []string{"Upgrade whichever side the finding names, or remove KexAlgorithms overrides (sshd_config, ssh_config, system crypto policies)."},
			Snippets: []report.Snippet{{Label: "sshd_config / ssh_config (OpenSSH 9.9+)", Code: "KexAlgorithms mlkem768x25519-sha256,sntrup761x25519-sha512,curve25519-sha256"}}})
	}
	if s := labels(func(g Connection) bool { return g.Protocol == "IKEv2" && g.Class == ClassClassical }, byServer); len(s) > 0 {
		out = append(out, report.Recommendation{ID: "ike-mlkem", Priority: report.PriorityNow, Services: s,
			Title:    "Add ML-KEM to IKEv2 proposals",
			Why:      "These IPsec tunnels established keys with classical Diffie-Hellman only, so recorded tunnel traffic is exposed. RFC 9370 lets IKEv2 add an ML-KEM exchange next to the classical one.",
			Steps:    []string{"On both peers, add an additional key exchange with ML-KEM-768 to the IKE proposal, then re-capture: the responder's IKE_SA_INIT should list ML-KEM-768."},
			Snippets: []report.Snippet{{Label: "strongSwan 6.0+ (swanctl.conf)", Code: "proposals = aes256gcm16-prfsha384-x25519-ke1_mlkem768"}},
			Refs:     []report.Ref{{Label: "RFC 9370", URL: "https://www.rfc-editor.org/rfc/rfc9370"}, {Label: "draft-ietf-ipsecme-ikev2-mlkem", URL: "https://datatracker.ietf.org/doc/draft-ietf-ipsecme-ikev2-mlkem/"}}})
	}
	if s := labels(func(g Connection) bool { return g.Outcome == "wireguard" }, byServer); len(s) > 0 {
		out = append(out, report.Recommendation{ID: "wireguard-psk", Priority: report.PriorityNow, Services: s,
			Title: "Add a post-quantum layer to WireGuard",
			Why:   "WireGuard's handshake is X25519 only. Its optional pre-shared key is mixed into every handshake, so a pre-shared key that is itself established post-quantum protects recorded traffic.",
			Steps: []string{"Configure PresharedKey on each peer, and rotate it with a post-quantum key exchange (for example Rosenpass) rather than a static secret.", "Or move these tunnels to IPsec with ML-KEM or TLS-based VPNs with X25519MLKEM768."}})
	}
	out = append(out, inspect.Recommend(r.Findings)...)
	order := map[report.Priority]int{report.PriorityNow: 0, report.PriorityHarden: 1, report.PriorityPlan: 2}
	sort.SliceStable(out, func(i, j int) bool { return order[out[i].Priority] < order[out[j].Priority] })
	return out
}
