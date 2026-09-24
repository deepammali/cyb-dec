// Package services holds the catalog of scannable services and orchestrates a
// scan across them. Phase 1 covered implicit-TLS HTTPS; Phase 2 adds the other
// TLS services (implicit TLS and STARTTLS). Later phases add SSH, QUIC, and IKEv2.
package services

import (
	"strings"
	"sync"
	"time"

	"pqscan/internal/probe"
	"pqscan/internal/report"
)

// Service describes one scannable endpoint type.
type Service struct {
	Name     string
	Port     int
	Preamble probe.Preamble // nil = implicit TLS; otherwise a STARTTLS negotiation
	Default  bool           // scanned when the user does not choose services
}

// Catalog is the built-in service list (Phase 1 + 2).
var Catalog = []Service{
	// implicit TLS
	{Name: "HTTPS", Port: 443, Default: true},
	{Name: "SMTPS", Port: 465},
	{Name: "IMAPS", Port: 993},
	{Name: "POP3S", Port: 995},
	{Name: "FTPS", Port: 990},
	{Name: "LDAPS", Port: 636},
	{Name: "DoT", Port: 853},
	{Name: "MQTT", Port: 8883},
	{Name: "AMQP", Port: 5671},
	{Name: "MongoDB", Port: 27017},
	{Name: "Redis", Port: 6379},
	{Name: "Syslog-TLS", Port: 6514},
	// STARTTLS
	{Name: "SMTP", Port: 25, Preamble: probe.SMTPStartTLS},
	{Name: "SMTP-submission", Port: 587, Preamble: probe.SMTPStartTLS},
	{Name: "IMAP", Port: 143, Preamble: probe.IMAPStartTLS},
	{Name: "POP3", Port: 110, Preamble: probe.POP3StartTLS},
	{Name: "FTP", Port: 21, Preamble: probe.FTPStartTLS},
	{Name: "PostgreSQL", Port: 5432, Preamble: probe.PostgresStartTLS},
}

// Default returns the services scanned when the user does not choose (HTTPS).
func Default() []Service {
	var out []Service
	for _, s := range Catalog {
		if s.Default {
			out = append(out, s)
		}
	}
	return out
}

// Select resolves service names to catalog entries. "all" selects the whole
// catalog; unknown names are ignored; an empty selection yields Default().
func Select(names []string) []Service {
	want := map[string]bool{}
	for _, n := range names {
		for _, part := range strings.FieldsFunc(n, func(r rune) bool { return r == ',' || r == ' ' }) {
			p := strings.ToLower(strings.TrimSpace(part))
			if p != "" {
				want[p] = true
			}
		}
	}
	if len(want) == 0 {
		return Default()
	}
	if want["all"] {
		return append([]Service(nil), Catalog...)
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

// Scan probes each service for host concurrently and returns the host-level
// report. The host must already have passed safety.Validate.
func Scan(host string, svcs []Service, timeout time.Duration) report.HostReport {
	reports := make([]report.ServiceReport, len(svcs))
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for i, s := range svcs {
		wg.Add(1)
		go func(i int, s Service) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			res := probe.ProbeTLS(s.Name, host, s.Port, host, s.Preamble, timeout)
			reports[i] = report.ForService(res)
		}(i, s)
	}
	wg.Wait()
	return report.Rollup(host, reports)
}
