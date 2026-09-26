// Package report turns raw probe results into states, verdicts, one-line
// headlines, and recommendations, shared by the web UI, JSON API, and CLI so
// wording never diverges.
package report

import (
	"fmt"
	"strings"

	"pqscan/internal/probe"
)

type Verdict string

const (
	Ready        Verdict = "ready"
	NotReady     Verdict = "not_ready"
	Undetermined Verdict = "undetermined"
)

// Label is a short human label for a verdict.
func (v Verdict) Label() string {
	switch v {
	case Ready:
		return "Post-quantum"
	case NotReady:
		return "Not post-quantum"
	default:
		return "Couldn't determine"
	}
}

// State is what a service's probe established, finer-grained than Verdict: a
// closed port is not an unknown, it is an absent attack surface.
type State string

const (
	StatePQ         State = "pq"          // negotiates post-quantum key exchange
	StateClassical  State = "classical"   // reachable, classical key exchange only
	StateClosed     State = "closed"      // connection refused
	StateNoResponse State = "no_response" // timed out or unreachable
	StateError      State = "error"       // reachable but the probe failed (incl. plaintext)
)

// ServiceReport pairs a probe result with its state, verdict, headline, and an
// assessment of how far the result can be trusted.
type ServiceReport struct {
	probe.ServiceResult
	State      State            `json:"state"`
	Verdict    Verdict          `json:"verdict"`
	Headline   string           `json:"headline"`
	Assessment Assessment       `json:"assessment"`
	Addresses  []string         `json:"addresses,omitempty"`  // every address tested for this service
	PerAddress []AddressOutcome `json:"perAddress,omitempty"` // set when addresses disagree
}

// AddressOutcome is one address's result when the addresses behind a name
// disagree.
type AddressOutcome struct {
	Address         string `json:"address"`
	State           State  `json:"state"`
	NegotiatedGroup string `json:"negotiatedGroup,omitempty"`
	Headline        string `json:"headline"`
}

// Counts tallies services by state.
type Counts struct {
	PQ         int `json:"pq"`
	Classical  int `json:"classical"`
	Closed     int `json:"closed"`
	NoResponse int `json:"noResponse"`
	Error      int `json:"error"`
}

// HostReport is the host-level rollup across all scanned services.
type HostReport struct {
	Host            string           `json:"host"`
	Target          string           `json:"target,omitempty"` // the estate entry: host, or host:port when one port was named
	Services        []ServiceReport  `json:"services"`
	Verdict         Verdict          `json:"verdict"`
	Headline        string           `json:"headline"`
	Counts          Counts           `json:"counts"`
	Planned         int              `json:"planned"`
	Partial         bool             `json:"partial,omitempty"` // stopped before every planned service ran
	Recommendations []Recommendation `json:"recommendations"`
	Controls        []probe.Control  `json:"controls"`
	Path            *PathCheck       `json:"path,omitempty"`
}

// ForService derives the state, verdict, headline, and assessment for one
// probed service.
func ForService(r probe.ServiceResult, env Env) ServiceReport {
	sr := ServiceReport{ServiceResult: r, State: stateOf(r)}
	sr.Assessment = assess(sr, env)
	switch {
	case sr.Assessment.Confidence == ConfInconsistent:
		sr.Verdict = Undetermined
	case sr.State == StatePQ:
		sr.Verdict = Ready
	case sr.State == StateClassical, isPlaintext(r):
		sr.Verdict = NotReady
	default:
		sr.Verdict = Undetermined
	}
	sr.Headline = headline(sr)
	return sr
}

func supportedNotPreferred(r probe.ServiceResult) bool {
	return r.Kind != "ssh" && !r.PQKeyExchange && r.Forced != nil && r.Forced.Completed
}

func isPlaintext(r probe.ServiceResult) bool { return r.ErrorKind == "no_starttls" }

// poolMixed reports whether identical offers to one address got both ML-KEM and
// classical answers: direct evidence of differently configured servers behind it.
func poolMixed(r probe.ServiceResult) bool {
	var pq, classical bool
	for _, s := range r.OfferSamples {
		switch {
		case strings.Contains(s, "MLKEM"):
			pq = true
		case s != "" && s != "error":
			classical = true
		}
	}
	return pq && classical
}

func stateOf(r probe.ServiceResult) State {
	if r.Error == "" && poolMixed(r) {
		return StateClassical // some connections get classical key exchange
	}
	if r.Error != "" {
		switch {
		case r.ErrorKind == "refused":
			return StateClosed
		case !r.Reachable && (r.ErrorKind == "timeout" || r.ErrorKind == "unreachable"):
			return StateNoResponse
		default:
			return StateError
		}
	}
	if r.PQKeyExchange {
		return StatePQ
	}
	if r.Reachable {
		return StateClassical
	}
	return StateError
}

func headline(sr ServiceReport) string {
	r := sr.ServiceResult
	switch sr.State {
	case StatePQ:
		switch {
		case r.Kind == "ssh":
			return fmt.Sprintf("Advertises %s, a post-quantum hybrid key exchange.", r.BestPQGroup)
		case sr.Assessment.Confidence == ConfInconsistent:
			return "Checks disagree: the server chose ML-KEM on one connection and refused it on another."
		case sr.Assessment.Confidence == ConfPartial:
			return fmt.Sprintf("Post-quantum only with clients that offer %s; browsers offering X25519MLKEM768 get %s.", pqGroups(r), orDash(r.NegotiatedGroup))
		}
		return fmt.Sprintf("Negotiates %s, a post-quantum hybrid key exchange.", r.NegotiatedGroup)
	case StateClassical:
		switch {
		case poolMixed(r):
			n := 0
			for _, s := range r.OfferSamples {
				if s != "" && s != "error" && !strings.Contains(s, "MLKEM") {
					n++
				}
			}
			return fmt.Sprintf("Mixed pool: %d of %d identical offers got classical key exchange, so some servers behind this address aren't post-quantum.", n, len(r.OfferSamples))
		case supportedNotPreferred(r):
			return fmt.Sprintf("Supports X25519MLKEM768 but prefers %s, so clients offering both get classical key exchange.", orDash(r.NegotiatedGroup))
		case r.Kind == "ssh":
			return "Advertises no post-quantum key exchange: sessions recorded today can be decrypted later."
		case strings.HasSuffix(r.BestPQGroup, "(legacy)"):
			return "Accepts only the deprecated Kyber draft group, which current clients no longer offer."
		case r.TLSVersion == "TLS 1.2" || strings.HasPrefix(r.NegotiatedGroup, "none"):
			return "Negotiates TLS 1.2, which has no post-quantum key exchange."
		case r.NegotiatedGroup != "":
			return fmt.Sprintf("Chose %s over the offered ML-KEM groups: classical key exchange.", r.NegotiatedGroup)
		default:
			return "Refused every ML-KEM offer: classical key exchange only."
		}
	case StateClosed:
		return "Port closed (connection refused): nothing is listening, so nothing to record."
	case StateNoResponse:
		if r.ErrorKind == "unreachable" {
			return "Host unreachable from this scanner."
		}
		return "No response within the timeout: filtered by a firewall, or the service is down."
	default:
		switch r.ErrorKind {
		case "no_starttls":
			return "Accepts connections but offers no TLS: traffic on this port is plaintext."
		case "dns":
			return "Host name did not resolve."
		}
		return "Could not complete the probe: " + strings.TrimSuffix(r.Error, ".") + "."
	}
}

// Rollup summarizes the scanned services for a host. planned is how many
// services the scan intended to run; partial marks a scan stopped early.
func Rollup(host string, svcs []ServiceReport, planned int, partial bool, env Env) HostReport {
	hr := HostReport{Host: host, Services: svcs, Planned: planned, Partial: partial, Controls: env.Controls, Path: env.Path}
	plaintext, unverified, narrow := 0, 0, 0
	for _, s := range svcs {
		switch s.Assessment.Confidence {
		case ConfInconsistent:
			unverified++
		case ConfPartial:
			narrow++
		}
		switch s.State {
		case StatePQ:
			hr.Counts.PQ++
		case StateClassical:
			hr.Counts.Classical++
		case StateClosed:
			hr.Counts.Closed++
		case StateNoResponse:
			hr.Counts.NoResponse++
		default:
			hr.Counts.Error++
		}
		if isPlaintext(s.ServiceResult) {
			plaintext++
		}
	}
	c := hr.Counts
	exposed := c.PQ + c.Classical + plaintext
	notPQ := c.Classical + plaintext

	switch {
	case len(svcs) == 0:
		hr.Verdict, hr.Headline = Undetermined, "No services were scanned."
	case exposed == 0 && c.Closed == len(svcs):
		hr.Verdict, hr.Headline = Undetermined, "Nothing is listening on the scanned ports."
	case exposed == 0:
		hr.Verdict, hr.Headline = Undetermined, "No scanned service could be assessed."
	case notPQ == 0 && exposed == 1:
		hr.Verdict, hr.Headline = Ready, "The one exposed service uses post-quantum key exchange."
	case notPQ == 0:
		hr.Verdict, hr.Headline = Ready, fmt.Sprintf("All %d exposed services use post-quantum key exchange.", exposed)
	case exposed == 1:
		hr.Verdict = NotReady
		if plaintext == 1 {
			hr.Headline = "The one exposed service sends plaintext."
		} else {
			hr.Headline = "The one exposed service uses classical key exchange."
		}
	case c.PQ == 0:
		hr.Verdict, hr.Headline = NotReady, fmt.Sprintf("None of the %d exposed services use post-quantum key exchange.", exposed)
	default:
		hr.Verdict, hr.Headline = NotReady, fmt.Sprintf("%d of %d exposed services are not post-quantum.", notPQ, exposed)
	}
	if plaintext > 0 && exposed > 1 {
		hr.Headline = strings.TrimSuffix(hr.Headline, ".") + fmt.Sprintf("; %d %s plaintext.", plaintext, plural(plaintext, "sends", "send"))
	}
	if narrow > 0 {
		hr.Headline = strings.TrimSuffix(hr.Headline, ".") + fmt.Sprintf("; %d only for some clients.", narrow)
	}
	if unverified > 0 {
		hr.Headline = strings.TrimSuffix(hr.Headline, ".") + fmt.Sprintf("; %d %s re-checking (checks disagreed).", unverified, plural(unverified, "needs", "need"))
		if hr.Verdict == Ready {
			hr.Verdict = Undetermined
		}
	}
	if len(env.Controls) > 0 && !probe.ControlsPassed(env.Controls) {
		hr.Verdict = Undetermined
		hr.Headline = "Engine controls failed, so these results can't be trusted. " + hr.Headline
	}
	hr.Recommendations = Recommend(svcs)
	return hr
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
