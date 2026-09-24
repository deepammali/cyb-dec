// Command pqscan checks whether a host's secure services use post-quantum key
// exchange (ML-KEM), from the command line.
//
//	pqscan cloudflare.com
//	pqscan --json example.com
//	pqscan --services HTTPS --timeout 10s host
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"pqscan/internal/probe"
	"pqscan/internal/report"
	"pqscan/internal/safety"
	"pqscan/internal/services"
)

func main() {
	jsonOut := flag.Bool("json", false, "emit JSON")
	svcList := flag.String("services", "", "comma-separated services (e.g. HTTPS,SMTP,IMAP); 'all' for the whole catalog; default: HTTPS")
	timeout := flag.Duration("timeout", probe.DefaultTimeout, "per-probe timeout")
	selftest := flag.Bool("selftest", false, "verify the probe engine against a local PQC server and exit")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: pqscan [flags] <host>\n\nChecks post-quantum readiness of a host's secure services.\n\nflags:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *selftest {
		if err := probe.SelfCalibrate(); err != nil {
			fmt.Fprintln(os.Stderr, "self-calibration FAILED:", err)
			os.Exit(1)
		}
		fmt.Println("self-calibration OK: engine detects X25519MLKEM768")
		os.Exit(0)
	}

	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}

	host, err := safety.Validate(flag.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}

	svcs := services.Select(strings.Split(*svcList, ","))
	hr := services.Scan(host, svcs, *timeout)

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(hr)
	} else {
		printHuman(hr)
	}

	switch hr.Verdict {
	case report.Ready:
		os.Exit(0)
	case report.NotReady:
		os.Exit(1)
	default:
		os.Exit(3)
	}
}

func printHuman(hr report.HostReport) {
	fmt.Printf("\nPQC readiness for %s\n", hr.Host)
	fmt.Printf("Overall: %s — %s\n", mark(hr.Verdict), hr.Summary)
	for _, s := range hr.Services {
		fmt.Printf("\n  %s (port %d): %s\n", s.Service, s.Port, mark(s.Verdict))
		if s.TLSVersion != "" {
			fmt.Printf("    %s, %s\n", s.TLSVersion, s.CipherSuite)
		}
		if s.CertSigAlg != "" {
			fmt.Printf("    cert signature: %s (expires %s)\n", s.CertSigAlg, s.CertNotAfter)
		}
		for _, g := range s.Groups {
			state := "no"
			if g.Supported {
				state = "YES"
			}
			line := fmt.Sprintf("    [%s] %s", state, g.Group)
			if g.Note != "" {
				line += "  — " + g.Note
			}
			fmt.Println(line)
		}
		fmt.Printf("    %s\n", wrap(s.Briefing, 76, "    "))
	}
	fmt.Println()
}

func mark(v report.Verdict) string {
	switch v {
	case report.Ready:
		return "OK  " + v.Label()
	case report.NotReady:
		return "!!  " + v.Label()
	default:
		return "??  " + v.Label()
	}
}

func wrap(s string, width int, indent string) string {
	words := strings.Fields(s)
	var b strings.Builder
	col := 0
	for i, w := range words {
		if col > 0 && col+1+len(w) > width {
			b.WriteString("\n" + indent)
			col = 0
		} else if i > 0 && col > 0 {
			b.WriteString(" ")
			col++
		}
		b.WriteString(w)
		col += len(w)
	}
	return b.String()
}
