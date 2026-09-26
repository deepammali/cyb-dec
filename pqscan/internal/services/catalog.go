// Package services holds the catalog of scannable services, role presets, and
// the protocols a user-supplied port can be probed as, and orchestrates a scan.
package services

import (
	"fmt"
	"strings"

	"pqscan/internal/probe"
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
	HTTP     bool           `json:"-"` // speaks HTTPS: check whether a CDN/proxy terminates TLS
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
	{Name: "HTTPS", Port: 443, Group: "Implicit TLS", Protocol: "tls", HTTP: true},
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
		s.HTTP = port == 443 || port == 8443
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
