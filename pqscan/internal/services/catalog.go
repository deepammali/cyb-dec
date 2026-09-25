// Package services holds the catalog of scannable services, role presets, and
// the protocols a user-supplied port can be probed as, and orchestrates a scan.
package services

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"pqscan/internal/probe"
	"pqscan/internal/report"
	"pqscan/internal/safety"
)

// Family selects which prober handles a service.
type Family int

const (
	FamilyTLS Family = iota // implicit TLS or STARTTLS
	FamilySSH               // SSH transport (reads KEXINIT)
)

// Service describes one scannable endpoint type.
type Service struct {
	Name     string         `json:"name"`
	Port     int            `json:"port"`
	Group    string         `json:"group"`    // UI grouping: Implicit TLS, STARTTLS, SSH
	Protocol string         `json:"protocol"` // tls, smtp+starttls, ssh, …
	Family   Family         `json:"-"`
	Preamble probe.Preamble `json:"-"` // TLS family: nil = implicit TLS
	Auto     bool           `json:"-"` // detect the protocol before probing (host:port scans)
}

func implicit(name string, port int) Service {
	return Service{Name: name, Port: port, Group: "Implicit TLS", Protocol: "tls"}
}

func starttls(name string, port int, proto string, pre probe.Preamble) Service {
	return Service{Name: name, Port: port, Group: "STARTTLS", Protocol: proto, Preamble: pre}
}

// Catalog is the built-in service list, HTTPS first so the most common answer
// arrives first.
var Catalog = []Service{
	implicit("HTTPS", 443),
	implicit("SMTPS", 465),
	implicit("IMAPS", 993),
	implicit("POP3S", 995),
	implicit("FTPS", 990),
	implicit("LDAPS", 636),
	implicit("DoT", 853),
	implicit("MQTT", 8883),
	implicit("AMQP", 5671),
	implicit("MongoDB", 27017),
	implicit("Redis", 6379),
	implicit("Syslog-TLS", 6514),
	starttls("SMTP", 25, "smtp+starttls", probe.SMTPStartTLS),
	starttls("SMTP-submission", 587, "smtp+starttls", probe.SMTPStartTLS),
	starttls("IMAP", 143, "imap+starttls", probe.IMAPStartTLS),
	starttls("POP3", 110, "pop3+starttls", probe.POP3StartTLS),
	starttls("FTP", 21, "ftp+authtls", probe.FTPStartTLS),
	starttls("PostgreSQL", 5432, "postgres+sslrequest", probe.PostgresStartTLS),
	// SSH covers SSH, SFTP, SCP, and Git-over-SSH: all run over the SSH transport.
	{Name: "SSH", Port: 22, Group: "SSH", Protocol: "ssh", Family: FamilySSH},
}

// Preset is a role-based selection of catalog services.
type Preset struct {
	ID       string   `json:"id"`
	Label    string   `json:"label"`
	Services []string `json:"services"`
}

// Presets map how people think about a host ("my mail server") to services.
// Together web, mail, remote, data, and infra cover the whole catalog.
var Presets = []Preset{
	{ID: "all", Label: "Everything"},
	{ID: "web", Label: "Web", Services: []string{"HTTPS"}},
	{ID: "mail", Label: "Mail", Services: []string{"SMTP", "SMTP-submission", "SMTPS", "IMAP", "IMAPS", "POP3", "POP3S"}},
	{ID: "remote", Label: "Remote access", Services: []string{"SSH", "FTP", "FTPS"}},
	{ID: "data", Label: "Data", Services: []string{"PostgreSQL", "MongoDB", "Redis", "MQTT", "AMQP"}},
	{ID: "infra", Label: "Infra", Services: []string{"LDAPS", "DoT", "Syslog-TLS"}},
}

func init() {
	for i := range Presets {
		if Presets[i].ID == "all" {
			for _, s := range Catalog {
				Presets[i].Services = append(Presets[i].Services, s.Name)
			}
		}
	}
}

// Select resolves service names and preset IDs (case-insensitive) to catalog
// entries in catalog order. An empty selection means the whole catalog.
func Select(names []string) ([]Service, error) {
	want := map[string]bool{}
	for _, n := range names {
		for _, part := range strings.FieldsFunc(n, func(r rune) bool { return r == ',' || r == ' ' }) {
			p := strings.ToLower(strings.TrimSpace(part))
			if p == "" {
				continue
			}
			if ps, ok := presetByID(p); ok {
				for _, s := range ps.Services {
					want[strings.ToLower(s)] = true
				}
				continue
			}
			if _, ok := byName(p); !ok {
				return nil, fmt.Errorf("unknown service or preset %q (presets: web, mail, remote, data, infra, all)", part)
			}
			want[p] = true
		}
	}
	if len(want) == 0 {
		return append([]Service(nil), Catalog...), nil
	}
	var out []Service
	for _, s := range Catalog {
		if want[strings.ToLower(s.Name)] {
			out = append(out, s)
		}
	}
	return out, nil
}

func presetByID(id string) (Preset, bool) {
	for _, p := range Presets {
		if p.ID == id {
			return p, true
		}
	}
	return Preset{}, false
}

func byName(lower string) (Service, bool) {
	for _, s := range Catalog {
		if strings.ToLower(s.Name) == lower {
			return s, true
		}
	}
	return Service{}, false
}

// Protocol is a way to probe a user-supplied port.
type Protocol struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

// Protocols lists the choices for a host:port scan; "auto" detects from the
// server's greeting.
var Protocols = []Protocol{
	{"auto", "Auto-detect"},
	{"tls", "TLS (implicit)"},
	{"ssh", "SSH"},
	{"smtp", "SMTP + STARTTLS"},
	{"imap", "IMAP + STARTTLS"},
	{"pop3", "POP3 + STARTTLS"},
	{"ftp", "FTP + AUTH TLS"},
	{"postgres", "PostgreSQL + SSLRequest"},
}

// ForPort builds the one-off service for a host:port scan with the given protocol.
func ForPort(proto string, port int) (Service, error) {
	switch strings.ToLower(proto) {
	case "", "auto":
		return Service{Name: fmt.Sprintf("Port %d", port), Port: port, Group: "Custom", Protocol: "auto", Auto: true}, nil
	case "tls":
		s := implicit("TLS", port)
		s.Group = "Custom"
		return s, nil
	case "ssh":
		return Service{Name: "SSH", Port: port, Group: "Custom", Protocol: "ssh", Family: FamilySSH}, nil
	case "smtp":
		return starttls("SMTP", port, "smtp+starttls", probe.SMTPStartTLS), nil
	case "imap":
		return starttls("IMAP", port, "imap+starttls", probe.IMAPStartTLS), nil
	case "pop3":
		return starttls("POP3", port, "pop3+starttls", probe.POP3StartTLS), nil
	case "ftp":
		return starttls("FTP", port, "ftp+authtls", probe.FTPStartTLS), nil
	case "postgres", "postgresql":
		return starttls("PostgreSQL", port, "postgres+sslrequest", probe.PostgresStartTLS), nil
	}
	return Service{}, fmt.Errorf("unknown protocol %q (auto, tls, ssh, smtp, imap, pop3, ftp, postgres)", proto)
}

// probeOne runs the right prober for s, detecting the protocol first if asked.
func probeOne(host string, s Service, timeout time.Duration) probe.ServiceResult {
	if s.Auto {
		proto, greeting, err := probe.Detect(host, s.Port, timeout)
		if err != nil {
			return probe.ServiceResult{
				Service: s.Name, Kind: "tls", Protocol: "auto", Host: host, Port: s.Port,
				Banner: greeting, Error: err.Error(), ErrorKind: probe.ErrorKind(err),
			}
		}
		detected, _ := ForPort(proto, s.Port)
		res := probeOne(host, detected, timeout)
		res.Detected = true
		return res
	}
	var res probe.ServiceResult
	if s.Family == FamilySSH {
		res = probe.ProbeSSH(s.Name, host, s.Port, timeout)
	} else {
		res = probe.ProbeTLS(s.Name, host, s.Port, host, s.Preamble, timeout)
	}
	res.Protocol = s.Protocol
	return res
}

// CheckPath probes a reference server known to support ML-KEM, to learn whether
// this scanner's network path carries ML-KEM handshakes. If it doesn't, every
// classical result from this scanner may be a false negative.
func CheckPath(reference string, timeout time.Duration) *report.PathCheck {
	pc := &report.PathCheck{Reference: reference}
	host, port, err := safety.ParseTarget(reference)
	if err != nil {
		pc.Error = err.Error()
		return pc
	}
	if port == 0 {
		port = 443
	}
	pc.Reference = net.JoinHostPort(host, strconv.Itoa(port))
	r := probe.ProbeTLS("reference", host, port, host, nil, timeout)
	if r.Error != "" {
		pc.Error = r.Error
		return pc
	}
	if h, _, err := net.SplitHostPort(r.Address); err == nil {
		if ip, err := netip.ParseAddr(h); err == nil && ip.IsLoopback() {
			pc.Loopback = true
		}
	}
	offered := len(r.Groups) > 0 && r.Groups[0].Supported
	forced := r.Forced != nil && r.Forced.Completed
	pc.Carried = offered || forced
	outcome := "did not complete"
	if forced {
		outcome = "completed"
	}
	pc.Detail = fmt.Sprintf("server chose %s; ML-KEM-only handshake %s", orDash(r.NegotiatedGroup), outcome)
	return pc
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

// Scan probes every service and returns the host report.
func Scan(host string, svcs []Service, timeout time.Duration, env report.Env) report.HostReport {
	return ScanStream(context.Background(), host, svcs, timeout, env, nil)
}

// ScanStream probes services concurrently, calling emit (serialized) as each one
// finishes. Once ctx is cancelled it launches no more probes, emits nothing
// further, and returns a partial report of what had finished.
func ScanStream(ctx context.Context, host string, svcs []Service, timeout time.Duration, env report.Env, emit func(report.ServiceReport)) report.HostReport {
	type indexed struct {
		i  int
		sr report.ServiceReport
	}
	var (
		mu   sync.Mutex
		done []indexed
		wg   sync.WaitGroup
	)
	sem := make(chan struct{}, 8)

launch:
	for i, s := range svcs {
		select {
		case <-ctx.Done():
			break launch
		case sem <- struct{}{}:
		}
		if ctx.Err() != nil {
			<-sem
			break
		}
		wg.Add(1)
		go func(i int, s Service) {
			defer wg.Done()
			defer func() { <-sem }()
			sr := report.ForService(probeOne(host, s, timeout), env)
			mu.Lock()
			defer mu.Unlock()
			if ctx.Err() != nil {
				return
			}
			done = append(done, indexed{i, sr})
			if emit != nil {
				emit(sr)
			}
		}(i, s)
	}

	finished := make(chan struct{})
	go func() { wg.Wait(); close(finished) }()
	select {
	case <-finished:
	case <-ctx.Done():
	}

	mu.Lock()
	snapshot := append([]indexed(nil), done...)
	mu.Unlock()
	sort.Slice(snapshot, func(a, b int) bool { return snapshot[a].i < snapshot[b].i })
	results := make([]report.ServiceReport, len(snapshot))
	for k, d := range snapshot {
		results[k] = d.sr
	}
	return report.Rollup(host, results, len(svcs), len(results) < len(svcs), env)
}
