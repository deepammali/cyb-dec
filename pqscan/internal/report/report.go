// Package report turns raw probe results into a verdict and a plain-language
// briefing, shared by the web UI, JSON API, and CLI so wording never diverges.
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
		return "Quantum-safe"
	case NotReady:
		return "Not ready"
	default:
		return "Couldn't determine"
	}
}

// ServiceReport pairs a probe result with its verdict and briefing.
type ServiceReport struct {
	probe.ServiceResult
	Verdict  Verdict `json:"verdict"`
	Briefing string  `json:"briefing"`
}

// HostReport is the host-level rollup across all scanned services.
type HostReport struct {
	Host     string          `json:"host"`
	Services []ServiceReport `json:"services"`
	Verdict  Verdict         `json:"verdict"`
	Summary  string          `json:"summary"`
}

// ForService derives the verdict and briefing for one probed service.
func ForService(r probe.ServiceResult) ServiceReport {
	sr := ServiceReport{ServiceResult: r}
	switch {
	case !r.Reachable && r.Error != "":
		sr.Verdict = Undetermined
	case r.PQKeyExchange:
		sr.Verdict = Ready
	default:
		sr.Verdict = NotReady
	}
	sr.Briefing = briefing(sr)
	return sr
}

func briefing(sr ServiceReport) string {
	r := sr.ServiceResult
	if r.Kind == "ssh" {
		return sshBriefing(sr)
	}
	switch sr.Verdict {
	case Ready:
		var supported []string
		for _, g := range r.Groups {
			if g.Supported {
				supported = append(supported, g.Group)
			}
		}
		return fmt.Sprintf(
			"%s on port %d negotiates post-quantum key exchange (%s). Traffic recorded today is protected against a future quantum computer, so it defeats the Harvest-Now-Decrypt-Later threat for the key exchange. Its certificate still uses a classical signature (%s), which is expected today and not a harvestable risk.",
			r.Service, r.Port, strings.Join(supported, ", "), orNA(r.CertSigAlg))
	case NotReady:
		return fmt.Sprintf(
			"%s on port %d does not offer any post-quantum key exchange (we offered ML-KEM first, with valid keys, and it chose classical). A recorded handshake today could be decrypted by a future quantum computer — the Harvest-Now-Decrypt-Later risk. Remediation: enable a hybrid ML-KEM group (e.g. X25519MLKEM768) on the terminating server, load balancer, or CDN.",
			r.Service, r.Port)
	default:
		reason := r.Error
		if reason == "" {
			reason = "no usable TLS response"
		}
		return fmt.Sprintf("%s on port %d could not be determined: %s.", r.Service, r.Port, reason)
	}
}

func sshBriefing(sr ServiceReport) string {
	r := sr.ServiceResult
	switch sr.Verdict {
	case Ready:
		var supported []string
		for _, g := range r.Groups {
			if g.Supported {
				supported = append(supported, g.Group)
			}
		}
		return fmt.Sprintf(
			"%s on port %d (%s) advertises post-quantum key exchange (%s), so a recorded session is protected against a future quantum computer.",
			r.Service, r.Port, orNA(r.Banner), strings.Join(supported, ", "))
	case NotReady:
		return fmt.Sprintf(
			"%s on port %d (%s) advertises no post-quantum key exchange, so a recorded session could be decrypted by a future quantum computer. Remediation: run OpenSSH 9.x+ and enable sntrup761x25519-sha512 or, on 9.9+, mlkem768x25519-sha256.",
			r.Service, r.Port, orNA(r.Banner))
	default:
		reason := r.Error
		if reason == "" {
			reason = "no SSH response"
		}
		return fmt.Sprintf("%s on port %d could not be determined: %s.", r.Service, r.Port, reason)
	}
}

func orNA(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

// Rollup summarizes several service reports for a host.
func Rollup(host string, svcs []ServiceReport) HostReport {
	hr := HostReport{Host: host, Services: svcs}
	var ready, notReady, undet int
	for _, s := range svcs {
		switch s.Verdict {
		case Ready:
			ready++
		case NotReady:
			notReady++
		default:
			undet++
		}
	}
	determined := ready + notReady
	undetSuffix := ""
	if undet > 0 {
		undetSuffix = fmt.Sprintf(" (%d not reachable)", undet)
	}
	switch {
	case len(svcs) == 0:
		hr.Verdict = Undetermined
		hr.Summary = "No services scanned."
	case determined == 0:
		hr.Verdict = Undetermined
		hr.Summary = "No scanned service was reachable."
	case notReady == 0:
		hr.Verdict = Ready
		hr.Summary = fmt.Sprintf("%d reachable service(s) quantum-safe%s.", ready, undetSuffix)
	case ready == 0:
		hr.Verdict = NotReady
		hr.Summary = fmt.Sprintf("%d reachable service(s) not quantum-safe%s.", notReady, undetSuffix)
	default:
		hr.Verdict = NotReady
		hr.Summary = fmt.Sprintf("%d ready, %d not ready of %d reachable%s.", ready, notReady, determined, undetSuffix)
	}
	return hr
}
