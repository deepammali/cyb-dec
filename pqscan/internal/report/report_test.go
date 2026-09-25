package report

import (
	"strings"
	"testing"

	"pqscan/internal/probe"
)

var passing = Env{Controls: []probe.Control{{Name: "c", Pass: true}}}

func group(name, chose string, supported bool) probe.GroupResult {
	return probe.GroupResult{Group: name, Supported: supported, Offered: name + " + X25519", ServerChose: chose}
}

func tlsPQ(name string, port int) probe.ServiceResult {
	return probe.ServiceResult{Service: name, Kind: "tls", Port: port, Reachable: true, TLSVersion: "TLS 1.3",
		PQKeyExchange: true, BestPQGroup: "X25519MLKEM768", NegotiatedGroup: "X25519MLKEM768",
		Groups: []probe.GroupResult{group("X25519MLKEM768", "X25519MLKEM768", true)},
		Forced: &probe.ForcedCheck{Group: "X25519MLKEM768", Completed: true}}
}

func tlsClassical(name string, port int) probe.ServiceResult {
	return probe.ServiceResult{Service: name, Kind: "tls", Port: port, Reachable: true, TLSVersion: "TLS 1.3",
		NegotiatedGroup: "X25519",
		Groups:          []probe.GroupResult{group("X25519MLKEM768", "X25519", false)},
		Forced:          &probe.ForcedCheck{Group: "X25519MLKEM768", Refused: true, Detail: "remote error: tls: handshake failure"}}
}

func failed(name string, port int, kind string) probe.ServiceResult {
	return probe.ServiceResult{Service: name, Kind: "tls", Port: port, Error: "boom", ErrorKind: kind}
}

func TestStateMapping(t *testing.T) {
	cases := []struct {
		in    probe.ServiceResult
		state State
		v     Verdict
	}{
		{tlsPQ("HTTPS", 443), StatePQ, Ready},
		{tlsClassical("HTTPS", 443), StateClassical, NotReady},
		{failed("SMTPS", 465, "refused"), StateClosed, Undetermined},
		{failed("Redis", 6379, "timeout"), StateNoResponse, Undetermined},
		{failed("Redis", 6379, "unreachable"), StateNoResponse, Undetermined},
		{failed("SMTP", 25, "no_starttls"), StateError, NotReady},
		{failed("IMAP", 143, "protocol"), StateError, Undetermined},
	}
	for _, tc := range cases {
		got := ForService(tc.in, passing)
		if got.State != tc.state || got.Verdict != tc.v {
			t.Errorf("%s/%s: got (%s, %s), want (%s, %s)", tc.in.Service, tc.in.ErrorKind, got.State, got.Verdict, tc.state, tc.v)
		}
		if got.Headline == "" {
			t.Errorf("%s: empty headline", tc.in.Service)
		}
	}
}

func TestHeadlines(t *testing.T) {
	if h := ForService(tlsClassical("HTTPS", 443), passing).Headline; !strings.Contains(h, "Chose X25519") {
		t.Errorf("classical headline = %q", h)
	}
	if h := ForService(failed("SMTP", 25, "no_starttls"), passing).Headline; !strings.Contains(h, "plaintext") {
		t.Errorf("plaintext headline = %q", h)
	}
	if h := ForService(failed("SMTPS", 465, "refused"), passing).Headline; !strings.Contains(h, "closed") {
		t.Errorf("closed headline = %q", h)
	}
}

// TestAssessment covers every way the two TLS checks can combine, plus the
// environment conditions that downgrade confidence.
func TestAssessment(t *testing.T) {
	notPreferred := tlsClassical("HTTPS", 443)
	notPreferred.Forced = &probe.ForcedCheck{Group: "X25519MLKEM768", Completed: true}

	inconsistent := tlsPQ("HTTPS", 443)
	inconsistent.Forced = &probe.ForcedCheck{Group: "X25519MLKEM768", Refused: true, Detail: "handshake failure"}

	partial := tlsClassical("HTTPS", 443)
	partial.PQKeyExchange, partial.BestPQGroup = true, "SecP256r1MLKEM768"
	partial.Groups = append(partial.Groups, group("SecP256r1MLKEM768", "SecP256r1MLKEM768", true))

	forcedTimeout := tlsPQ("HTTPS", 443)
	forcedTimeout.Forced = &probe.ForcedCheck{Group: "X25519MLKEM768", Detail: "timed out"}

	sshPQ := probe.ServiceResult{Service: "SSH", Kind: "ssh", Port: 22, Reachable: true, PQKeyExchange: true,
		BestPQGroup: "mlkem768x25519-sha256", Advertised: []string{"mlkem768x25519-sha256"}}

	badPath := Env{Controls: passing.Controls, Path: &PathCheck{Reference: "ref:443", Carried: false}}
	badControls := Env{Controls: []probe.Control{{Name: "c", Pass: false}}}

	cases := []struct {
		name       string
		in         probe.ServiceResult
		env        Env
		confidence string
		question   string
		verdict    Verdict
		headline   string
	}{
		{"confirmed PQ", tlsPQ("HTTPS", 443), passing, ConfConfirmed, qFP, Ready, "Negotiates X25519MLKEM768"},
		{"confirmed classical", tlsClassical("HTTPS", 443), passing, ConfConfirmed, qFN, NotReady, "Chose X25519"},
		{"supported, not preferred", notPreferred, passing, ConfConfirmed, qFN, NotReady, "Supports X25519MLKEM768 but prefers X25519"},
		{"checks disagree", inconsistent, passing, ConfInconsistent, qFP, Undetermined, "Checks disagree"},
		{"P-256 hybrid only", partial, passing, ConfPartial, qFP, Ready, "only with clients that offer SecP256r1MLKEM768"},
		{"forced check timed out", forcedTimeout, passing, ConfHigh, qFP, Ready, "Negotiates"},
		{"SSH list", sshPQ, passing, ConfConfirmed, qFP, Ready, "Advertises mlkem768x25519-sha256"},
		{"path strips ML-KEM", tlsClassical("HTTPS", 443), badPath, ConfLow, qFN, NotReady, "Chose X25519"},
		{"controls failed", tlsPQ("HTTPS", 443), badControls, ConfLow, qFP, Ready, "Negotiates"},
		{"plaintext", failed("SMTP", 25, "no_starttls"), passing, ConfConfirmed, qFN, NotReady, "plaintext"},
		{"closed", failed("SMTPS", 465, "refused"), passing, ConfNone, "", Undetermined, "closed"},
	}
	// A loopback reference says nothing about the path to a remote target.
	remote := tlsClassical("HTTPS", 443)
	remote.Address = "10.20.0.15:443"
	loopRef := Env{Controls: passing.Controls, Path: &PathCheck{Reference: "127.0.0.1:9443", Carried: true, Loopback: true}}
	sr := ForService(remote, loopRef)
	if last := sr.Assessment.Checks[len(sr.Assessment.Checks)-1]; last.Name != "Network path" || last.Outcome != "not_run" {
		t.Errorf("loopback reference, remote target: path check = %+v, want not_run", last)
	}
	local := tlsClassical("HTTPS", 443)
	local.Address = "127.0.0.1:9444"
	if last := ForService(local, loopRef).Assessment.Checks; last[len(last)-1].Outcome != "pass" {
		t.Errorf("loopback reference, loopback target: path check should pass, got %+v", last[len(last)-1])
	}

	for _, tc := range cases {
		sr := ForService(tc.in, tc.env)
		a := sr.Assessment
		if a.Confidence != tc.confidence || a.Question != tc.question || sr.Verdict != tc.verdict {
			t.Errorf("%s: got (%s, %q, %s), want (%s, %q, %s)", tc.name, a.Confidence, a.Question, sr.Verdict, tc.confidence, tc.question, tc.verdict)
		}
		if !strings.Contains(sr.Headline, tc.headline) {
			t.Errorf("%s: headline %q, want it to contain %q", tc.name, sr.Headline, tc.headline)
		}
		if tc.question != "" && (a.Answer == "" || a.Limits == "" || len(a.Checks) == 0) {
			t.Errorf("%s: readiness results need an answer, limits, and checks: %+v", tc.name, a)
		}
	}
}

func rollup(rs ...probe.ServiceResult) HostReport {
	var svcs []ServiceReport
	for _, r := range rs {
		svcs = append(svcs, ForService(r, passing))
	}
	return Rollup("h", svcs, len(svcs), false, passing)
}

func TestRollup(t *testing.T) {
	inconsistent := tlsPQ("HTTPS", 443)
	inconsistent.Forced = &probe.ForcedCheck{Refused: true}

	cases := []struct {
		name     string
		hr       HostReport
		verdict  Verdict
		headline string
	}{
		{"nothing scanned", rollup(), Undetermined, "No services were scanned."},
		{"all closed", rollup(failed("A", 1, "refused"), failed("B", 2, "refused")), Undetermined, "Nothing is listening on the scanned ports."},
		{"only timeouts", rollup(failed("A", 1, "timeout")), Undetermined, "No scanned service could be assessed."},
		{"one pq", rollup(tlsPQ("HTTPS", 443), failed("B", 2, "refused")), Ready, "The one exposed service uses post-quantum key exchange."},
		{"all pq", rollup(tlsPQ("HTTPS", 443), tlsPQ("IMAPS", 993)), Ready, "All 2 exposed services use post-quantum key exchange."},
		{"one classical", rollup(tlsClassical("HTTPS", 443)), NotReady, "The one exposed service uses classical key exchange."},
		{"none pq", rollup(tlsClassical("HTTPS", 443), tlsClassical("IMAPS", 993)), NotReady, "None of the 2 exposed services use post-quantum key exchange."},
		{"mixed with plaintext", rollup(tlsPQ("HTTPS", 443), tlsClassical("IMAPS", 993), failed("SMTP", 25, "no_starttls")), NotReady, "2 of 3 exposed services are not post-quantum; 1 sends plaintext."},
		{"unverified", rollup(inconsistent), Undetermined, "The one exposed service uses post-quantum key exchange; 1 needs re-checking (checks disagreed)."},
	}
	for _, tc := range cases {
		if tc.hr.Verdict != tc.verdict || tc.hr.Headline != tc.headline {
			t.Errorf("%s: got (%s, %q), want (%s, %q)", tc.name, tc.hr.Verdict, tc.hr.Headline, tc.verdict, tc.headline)
		}
	}
	hr := rollup(tlsPQ("HTTPS", 443), tlsClassical("IMAPS", 993), failed("A", 1, "refused"), failed("B", 2, "timeout"), failed("C", 3, "protocol"))
	want := Counts{PQ: 1, Classical: 1, Closed: 1, NoResponse: 1, Error: 1}
	if hr.Counts != want {
		t.Errorf("counts = %+v, want %+v", hr.Counts, want)
	}
}
