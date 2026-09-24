// Package services holds the catalog of scannable services and orchestrates a
// scan across them. Phase 1 covers implicit-TLS HTTPS; later phases add STARTTLS
// services, SSH, QUIC, and IKEv2 by extending the catalog and probe families.
package services

import (
	"strings"
	"time"

	"pqscan/internal/probe"
	"pqscan/internal/report"
)

// Family selects which prober handles a service.
type Family int

const (
	FamilyTLSImplicit Family = iota // dial TLS directly (HTTPS, IMAPS, ...)
	// Reserved for later phases: STARTTLS, SSH, QUIC, IKE.
)

// Service describes one scannable endpoint type.
type Service struct {
	Name   string
	Port   int
	Family Family
}

// Catalog is the built-in service list. Phase 1: HTTPS only.
var Catalog = []Service{
	{Name: "HTTPS", Port: 443, Family: FamilyTLSImplicit},
}

// Default returns the services scanned when the user does not choose.
func Default() []Service { return Catalog }

// Select resolves comma/space separated service names to catalog entries.
// Unknown names are ignored; an empty selection yields Default().
func Select(names []string) []Service {
	if len(names) == 0 {
		return Default()
	}
	want := map[string]bool{}
	for _, n := range names {
		for _, part := range strings.FieldsFunc(n, func(r rune) bool { return r == ',' || r == ' ' }) {
			want[strings.ToLower(strings.TrimSpace(part))] = true
		}
	}
	var out []Service
	for _, s := range Catalog {
		if want[strings.ToLower(s.Name)] {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return Default()
	}
	return out
}

// Scan probes each service for host and returns the host-level report. The host
// must already have passed safety.Validate.
func Scan(host string, svcs []Service, timeout time.Duration) report.HostReport {
	var reports []report.ServiceReport
	for _, s := range svcs {
		switch s.Family {
		case FamilyTLSImplicit:
			res := probe.ProbeTLS(s.Name, host, s.Port, host, timeout)
			reports = append(reports, report.ForService(res))
		}
	}
	return report.Rollup(host, reports)
}
