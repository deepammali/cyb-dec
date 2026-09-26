package report

import (
	"fmt"
	"net"
	"net/netip"
	"strings"

	"pqscan/internal/probe"
)

// Env is what a scan knows about its own trustworthiness, beyond each target.
type Env struct {
	Controls []probe.Control // engine calibration run before the scan
	Path     *PathCheck      // optional network-path check against a known ML-KEM server
}

// PathCheck records whether this scanner's network path carries ML-KEM
// handshakes, tested against a server known to support them. A middlebox that
// strips or breaks large ClientHellos makes every server look classical.
type PathCheck struct {
	Reference string `json:"reference"`
	Carried   bool   `json:"carried"`
	Loopback  bool   `json:"loopback,omitempty"` // reference is on this machine: it doesn't cross the network
	Detail    string `json:"detail"`
	Error     string `json:"error,omitempty"`
}

// coversTarget reports whether the path check says anything about the path to
// this target. A loopback reference only exercises the path to loopback targets.
func (p *PathCheck) coversTarget(r probe.ServiceResult) bool {
	if !p.Loopback {
		return true
	}
	host, _, err := net.SplitHostPort(r.Address)
	if err != nil {
		return false
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}

// Confidence levels, strongest first.
const (
	ConfConfirmed    = "confirmed"    // two independent checks agree (or the protocol makes one authoritative)
	ConfHigh         = "high"         // one decisive check; the confirming check couldn't run
	ConfPartial      = "partial"      // post-quantum only for some clients
	ConfInconsistent = "inconsistent" // checks disagree
	ConfMixed        = "mixed"        // directly observed: some servers behind the target are classical
	ConfLow          = "low"          // engine or path problem undermines the result
	ConfNone         = "none"         // not a readiness result (closed, no response, error)
)

// Check is one piece of evidence behind a result.
type Check struct {
	Name    string `json:"name"`
	Outcome string `json:"outcome"` // pq | classical | pass | fail | inconclusive | not_run
	Detail  string `json:"detail"`
}

// Assessment says how far a result can be trusted: which checks back it, which
// error (false positive or false negative) it could be, and whether that error
// was ruled out.
type Assessment struct {
	Confidence string  `json:"confidence"`
	Summary    string  `json:"summary"`
	Question   string  `json:"question,omitempty"` // "Could this be a false positive?" etc.
	Answer     string  `json:"answer,omitempty"`
	Checks     []Check `json:"checks,omitempty"`
	Limits     string  `json:"limits,omitempty"`
}

const (
	qFP = "Could this be a false positive?"
	qFN = "Could this be a false negative?"
)

// offerPQ reports the offer test's outcome for X25519MLKEM768, the group every
// current browser offers: "pq", "classical", or "inconclusive".
func offerOutcome(r probe.ServiceResult) (string, probe.GroupResult) {
	if len(r.Groups) == 0 {
		return "inconclusive", probe.GroupResult{}
	}
	g := r.Groups[0]
	switch {
	case g.Supported:
		return "pq", g
	case g.ServerChose != "" || g.Alerted:
		return "classical", g
	}
	return "inconclusive", g
}

func forcedOutcome(r probe.ServiceResult) string {
	switch {
	case r.Forced == nil:
		return "not_run"
	case r.Forced.Completed:
		return "pq"
	case r.Forced.Refused:
		return "classical"
	}
	return "inconclusive"
}

func assess(sr ServiceReport, env Env) Assessment {
	r := sr.ServiceResult
	limits := fmt.Sprintf("Valid for %s as reached from this scanner at scan time.", orAddr(r))
	switch {
	case len(r.OfferSamples) > 1 && !poolMixed(r):
		limits += fmt.Sprintf(" %d identical offers got the same answer, but a large load-balanced pool can hide a differently configured server that none of them reached.", len(r.OfferSamples))
	case r.Kind == "ssh":
		limits += " A load-balanced pool behind this address can hide a differently configured server."
	}

	switch sr.State {
	case StateClosed:
		return Assessment{Confidence: ConfNone, Summary: "Not a readiness result: the port refused the connection.",
			Limits: "Closed from this scanner's network. A firewall may treat other networks differently."}
	case StateNoResponse:
		return Assessment{Confidence: ConfNone, Summary: "Not a readiness result: nothing answered within the timeout.",
			Limits: "A firewall dropping packets, a stopped service, and a slow link (raise --timeout) all look the same from here."}
	case StateError:
		if !isPlaintext(r) {
			return Assessment{Confidence: ConfNone, Summary: "Not a readiness result: the probe could not finish.", Limits: r.Error}
		}
	}

	var a Assessment
	if isPlaintext(r) {
		a = Assessment{Confidence: ConfConfirmed, Summary: "Confirmed: the server itself refused to start TLS.",
			Question: qFN, Answer: "No. This isn't inferred: the server answered the TLS upgrade request with a refusal.",
			Checks: []Check{{Name: "TLS upgrade request", Outcome: "fail", Detail: r.Error}}}
	} else if r.Kind == "ssh" {
		outcome := "classical"
		if r.PQKeyExchange {
			outcome = "pq"
		}
		a.Checks = []Check{{Name: "Server's method list (KEXINIT)", Outcome: outcome, Detail: "Advertises: " + strings.Join(r.Advertised, ", ")}}
		if r.PQKeyExchange {
			a.Confidence, a.Summary, a.Question = ConfConfirmed, "Confirmed by the server's own list of key-exchange methods.", qFP
			a.Answer = fmt.Sprintf("Unlikely. The list is the server's own statement, and SSH uses the first method in the client's list that the server also supports (RFC 4253 §7.1). Clients that list %s first, as OpenSSH 9.0+ does by default, use it. A server that tailors its list to each client could differ for other clients; that is rare.", r.BestPQGroup)
		} else {
			a.Confidence, a.Summary, a.Question = ConfConfirmed, "Confirmed by the server's complete list of key-exchange methods.", qFN
			a.Answer = "No, for this server: its complete list contains no post-quantum method, so no client can negotiate one."
		}
	} else {
		offer, g0 := offerOutcome(r)
		forced := forcedOutcome(r)
		chose := g0.ServerChose
		if g0.Alerted {
			chose = "to refuse the offer"
		}
		offerDetail := fmt.Sprintf("Offered %s with valid keys (hand-crafted ClientHello, like a current browser) → server chose %s.", g0.Offered, orDash(chose))
		if offer == "inconclusive" {
			offerDetail = "Offer test could not complete: " + g0.Note
		}
		forcedDetail := "Full handshake offering only X25519MLKEM768 with a second, independent TLS client (Go crypto/tls): "
		switch forced {
		case "pq":
			forcedDetail += "completed."
		case "classical":
			forcedDetail += "refused (" + r.Forced.Detail + ")."
		case "inconclusive":
			forcedDetail += "could not run (" + r.Forced.Detail + ")."
		default:
			forcedDetail += "not run."
		}
		a.Checks = []Check{
			{Name: "Offer test", Outcome: offer, Detail: offerDetail},
			{Name: "Forced test", Outcome: forced, Detail: forcedDetail},
		}
		if len(r.OfferSamples) > 1 {
			outcome := "pass"
			if poolMixed(r) {
				outcome = "fail"
			}
			a.Checks = append(a.Checks, Check{Name: "Pool sampling", Outcome: outcome,
				Detail: fmt.Sprintf("%d identical offers to %s → server chose %s.", len(r.OfferSamples), orAddr(r), strings.Join(r.OfferSamples, ", "))})
		}

		switch sr.State {
		case StatePQ:
			a.Question = qFP
			switch {
			case offer == "pq" && forced == "pq":
				a.Confidence, a.Summary = ConfConfirmed, "Confirmed by two independent checks."
				a.Answer = "Ruled out. The server chose X25519MLKEM768 in its own ServerHello, and a second, independent TLS client completed a full handshake using only X25519MLKEM768."
			case offer == "pq" && forced == "classical":
				a.Confidence, a.Summary = ConfInconsistent, "Unverified: the two checks disagree."
				a.Answer = "Possible. The server chose ML-KEM on one connection but refused an ML-KEM-only handshake on another. Several servers with different settings may share this address. Re-scan, or scan each server directly, before relying on this result."
			case offer == "pq":
				a.Confidence, a.Summary = ConfHigh, "Backed by one decisive check; the confirming handshake could not run."
				a.Answer = "Unlikely. The server committed to X25519MLKEM768 in its ServerHello, which is the group it uses for the connection. The confirming handshake couldn't run, so the result is not double-checked."
			default:
				a.Confidence, a.Summary = ConfPartial, "Post-quantum only for some clients."
				a.Answer = fmt.Sprintf("Not false, but narrow. The server chose %s when a client offered it, but chose %s when offered X25519MLKEM768 + X25519, which is what current browsers send. Only clients that offer the P-256/P-384 hybrids (typically FIPS-configured ones) get post-quantum key exchange.", pqGroups(r), orDash(g0.ServerChose))
			}
		case StateClassical:
			a.Question = qFN
			switch {
			case poolMixed(r):
				a.Confidence, a.Summary = ConfMixed, "Mixed pool: observed directly across repeated connections."
				a.Answer = "No. Identical offers to the same address got different answers, so several servers with different settings share it. Connections that land on the classical ones get classical key exchange."
			case forced == "pq":
				a.Confidence, a.Summary = ConfConfirmed, "Confirmed: ML-KEM is supported but not preferred."
				a.Answer = fmt.Sprintf("No, for real clients. The server does support X25519MLKEM768 (the forced handshake completed), but it chose %s when offered both, as every current browser does. Real traffic gets classical key exchange.", orDash(g0.ServerChose))
			case forced == "classical":
				a.Confidence, a.Summary = ConfConfirmed, "Confirmed by two independent checks."
				a.Answer = "Ruled out for this network path. ML-KEM was offered first with a valid key and the server didn't take it; a second, independent TLS client offering only X25519MLKEM768 was refused too."
			default:
				a.Confidence, a.Summary = ConfHigh, "Backed by one decisive check; the confirming handshake could not run."
				a.Answer = "Unlikely. ML-KEM was offered first with a valid key and the server chose classical key exchange. The confirming handshake couldn't run, so the result is not double-checked."
			}
		}
	}

	// Engine calibration applies to every readiness result.
	switch {
	case len(env.Controls) == 0:
		a.Checks = append(a.Checks, Check{Name: "Engine controls", Outcome: "not_run", Detail: "Reference-server controls were not run for this scan."})
	case probe.ControlsPassed(env.Controls):
		a.Checks = append(a.Checks, Check{Name: "Engine controls", Outcome: "pass", Detail: fmt.Sprintf("All %d controls passed: known ML-KEM servers read post-quantum and known classical servers read classical, for TLS and SSH.", len(env.Controls))})
	default:
		a.Checks = append(a.Checks, Check{Name: "Engine controls", Outcome: "fail", Detail: "At least one reference-server control failed."})
		a.Confidence = ConfLow
		a.Summary = "Engine controls failed: don't rely on this result."
	}

	// The network path matters for TLS: a middlebox can strip ML-KEM offers.
	if r.Kind != "ssh" && !isPlaintext(r) {
		switch p := env.Path; {
		case p == nil:
			a.Checks = append(a.Checks, Check{Name: "Network path", Outcome: "not_run", Detail: "Not verified. Run with --reference <known ML-KEM server> to rule out a middlebox that strips ML-KEM offers."})
		case p.Error != "":
			a.Checks = append(a.Checks, Check{Name: "Network path", Outcome: "inconclusive", Detail: fmt.Sprintf("Reference %s could not be checked: %s", p.Reference, p.Error)})
		case !p.coversTarget(r):
			a.Checks = append(a.Checks, Check{Name: "Network path", Outcome: "not_run", Detail: fmt.Sprintf("Not verified for this target: reference %s is on this machine, so it doesn't cross the network to %s. Use a known ML-KEM server reached the same way as your targets.", p.Reference, orAddr(r))})
		case p.Carried:
			a.Checks = append(a.Checks, Check{Name: "Network path", Outcome: "pass", Detail: fmt.Sprintf("Reference %s negotiated ML-KEM through this path.", p.Reference)})
		default:
			a.Checks = append(a.Checks, Check{Name: "Network path", Outcome: "fail", Detail: fmt.Sprintf("Reference %s, a known ML-KEM server, read as classical from here.", p.Reference)})
			if sr.State == StateClassical {
				a.Confidence = ConfLow
				a.Summary = "Possibly a false negative: this scanner's network path doesn't carry ML-KEM."
				a.Answer = "Possible. A server known to support ML-KEM also read as classical from here, so something on the path (a proxy or middlebox) may be removing ML-KEM offers. Clients on the same path would also get classical key exchange, but the server itself may be ready."
			}
		}
	}
	if r.Edge != nil {
		limits += fmt.Sprintf(" TLS terminates at %s (%s): the origin server and the hops behind it are separate connections that weren't measured.", r.Edge.Name, r.Edge.Evidence)
	}
	a.Limits = limits
	return a
}

func pqGroups(r probe.ServiceResult) string {
	var out []string
	for _, g := range r.Groups {
		if g.Supported && !g.LowConfidence {
			out = append(out, g.Group)
		}
	}
	return strings.Join(out, ", ")
}

func orAddr(r probe.ServiceResult) string {
	if r.Address != "" {
		return r.Address
	}
	return fmt.Sprintf("%s:%d", r.Host, r.Port)
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}
