// Command pqscan checks whether a host's secure services use post-quantum key
// exchange (ML-KEM), from the command line.
//
//	pqscan mail.corp.local                 # every service in the catalog
//	pqscan --services mail,web example.com # role presets or service names
//	pqscan 10.0.0.5:2222                   # one port, protocol auto-detected
//	pqscan --json host
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"pqscan/internal/probe"
	"pqscan/internal/report"
	"pqscan/internal/safety"
	"pqscan/internal/services"
)

func main() {
	jsonOut := flag.Bool("json", false, "emit the JSON report")
	svcList := flag.String("services", "", "service names or presets (web, mail, remote, data, infra, all); default: all")
	protocol := flag.String("protocol", "auto", "for host:port targets: auto, tls, ssh, smtp, imap, pop3, ftp, postgres")
	timeout := flag.Duration("timeout", probe.DefaultTimeout, "per-probe timeout")
	reference := flag.String("reference", "", "host[:port] of a server known to support ML-KEM, to verify this machine's network path (off by default: no outside contact)")
	selftest := flag.Bool("selftest", false, "run the engine controls against local reference servers and exit")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: pqscan [flags] <host | host:port>\n\nChecks whether a host's services use post-quantum key exchange (ML-KEM).\n\nflags:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *selftest {
		controls := probe.RunControls()
		for _, c := range controls {
			mark := "PASS"
			if !c.Pass {
				mark = "FAIL"
			}
			fmt.Printf("%s  %s\n      expected: %s\n      got:      %s\n", mark, c.Name, c.Expect, c.Got)
		}
		if !probe.ControlsPassed(controls) {
			fmt.Fprintln(os.Stderr, "engine controls FAILED: results from this build are not trustworthy")
			os.Exit(1)
		}
		fmt.Println("all engine controls passed: no systematic false positives or false negatives on the reference servers")
		os.Exit(0)
	}
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}

	host, port, err := safety.ParseTarget(flag.Arg(0))
	if err == nil {
		err = safety.Resolve(host)
	}
	var svcs []services.Service
	if err == nil {
		if port > 0 {
			var s services.Service
			s, err = services.ForPort(*protocol, port)
			svcs = []services.Service{s}
		} else {
			svcs, err = services.Select([]string{*svcList})
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}

	env := report.Env{Controls: probe.RunControls()}
	if *reference != "" {
		env.Path = services.CheckPath(*reference, *timeout)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	start := time.Now()
	var finished atomic.Int32
	progress := func(report.ServiceReport) {}
	if !*jsonOut && isTerminal(os.Stderr) {
		progress = func(report.ServiceReport) {
			fmt.Fprintf(os.Stderr, "\r  probing %s … %d/%d  %.0fs ", host, finished.Add(1), len(svcs), time.Since(start).Seconds())
		}
	}
	hr := services.ScanStream(ctx, host, svcs, *timeout, env, progress)
	if !*jsonOut && isTerminal(os.Stderr) {
		fmt.Fprint(os.Stderr, "\r\033[K")
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(hr)
	} else {
		printHuman(hr, time.Since(start))
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

func isTerminal(f *os.File) bool {
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

// severity orders rows so the services that need action come first.
func severity(s report.ServiceReport) int {
	switch {
	case s.ErrorKind == "no_starttls":
		return 0
	case s.State == report.StateClassical:
		return 1
	case s.State == report.StateError:
		return 2
	case s.State == report.StatePQ:
		return 3
	}
	return 4
}

func keyExchange(s report.ServiceReport) string {
	switch {
	case s.State == report.StatePQ && s.Kind == "ssh":
		return s.BestPQGroup
	case s.State == report.StatePQ:
		if strings.Contains(s.NegotiatedGroup, "MLKEM") {
			return s.NegotiatedGroup
		}
		return s.BestPQGroup
	case s.State == report.StateClassical && s.Kind == "ssh":
		return "no post-quantum KEX"
	case s.State == report.StateClassical && strings.HasPrefix(s.NegotiatedGroup, "none"):
		return "TLS 1.2 · classical"
	case s.State == report.StateClassical && s.NegotiatedGroup != "":
		return s.NegotiatedGroup + " · classical"
	case s.State == report.StateClassical:
		return "classical"
	case s.ErrorKind == "no_starttls":
		return "plaintext (no TLS)"
	}
	return "—"
}

func status(s report.ServiceReport) string {
	switch {
	case s.State == report.StatePQ:
		return "✓ Post-quantum"
	case s.ErrorKind == "no_starttls":
		return "✕ Plaintext"
	case s.State == report.StateClassical:
		return "✕ Classical"
	case s.State == report.StateError:
		return "! Error"
	}
	return ""
}

func printHuman(hr report.HostReport, elapsed time.Duration) {
	fmt.Printf("\npqscan · %s · %s · %.1f s\n", hr.Host, time.Now().UTC().Format("2006-01-02 15:04 UTC"), elapsed.Seconds())
	fmt.Printf("%s — %s\n", strings.ToUpper(hr.Verdict.Label()), hr.Headline)
	if hr.Partial {
		fmt.Printf("Stopped — %d of %d services scanned.\n", len(hr.Services), hr.Planned)
	}
	fmt.Println(trustLine(hr))

	var rows, closed, silent []report.ServiceReport
	for _, s := range hr.Services {
		switch s.State {
		case report.StateClosed:
			closed = append(closed, s)
		case report.StateNoResponse:
			silent = append(silent, s)
		default:
			rows = append(rows, s)
		}
	}
	sort.SliceStable(rows, func(i, j int) bool { return severity(rows[i]) < severity(rows[j]) })

	if len(rows) > 0 {
		fmt.Printf("\n  %-17s %6s   %-30s %-16s %s\n", "SERVICE", "PORT", "KEY EXCHANGE", "STATUS", "CONFIDENCE")
		for _, s := range rows {
			name := s.Service
			if s.Detected {
				name += "*"
			}
			fmt.Printf("  %-17s %6d   %-30s %-16s %s\n", name, s.Port, keyExchange(s), status(s), s.Assessment.Confidence)
		}
	}
	if len(closed) > 0 {
		fmt.Printf("  %d closed: %s\n", len(closed), list(closed))
	}
	if len(silent) > 0 {
		fmt.Printf("  %d no response: %s\n", len(silent), list(silent))
	}
	for _, s := range rows {
		if s.Detected {
			fmt.Printf("  * protocol auto-detected as %s\n", s.Protocol)
			break
		}
	}

	if len(rows) > 0 {
		fmt.Println("\nEvidence")
		for _, s := range rows {
			fmt.Printf("  %s :%d — %s\n", s.Service, s.Port, s.Headline)
			a := s.Assessment
			fmt.Printf("    How sure: %s (%s)\n", a.Summary, a.Confidence)
			for _, c := range a.Checks {
				fmt.Printf("      %s %s: %s\n", checkMark(c.Outcome), c.Name, wrap(c.Detail, 64, "          "))
			}
			if a.Question != "" {
				fmt.Printf("    %s\n      %s\n", a.Question, wrap(a.Answer, 70, "      "))
			}
			if a.Limits != "" {
				fmt.Printf("    Limits: %s\n", wrap(a.Limits, 70, "      "))
			}
			if s.Banner != "" {
				fmt.Printf("    server: %s\n", s.Banner)
			}
			if s.TLSVersion != "" {
				line := fmt.Sprintf("    %s · %s", s.TLSVersion, s.CipherSuite)
				if s.CertSubject != "" {
					line += " · cert CN=" + s.CertSubject
				}
				if s.CertSigAlg != "" {
					line += fmt.Sprintf(" (%s, expires %s)", s.CertSigAlg, s.CertNotAfter)
				}
				fmt.Println(line)
			}
			for _, g := range s.Groups {
				if g.Offered != "" && (g.ServerChose != "" || g.Alerted) {
					chose := g.ServerChose
					if g.Alerted {
						chose = "refused (alert)"
					}
					fmt.Printf("    offered %-36s → %s\n", g.Offered, chose)
				}
			}
			if s.Kind == "ssh" && len(s.Advertised) > 0 {
				fmt.Printf("    advertises: %s\n", strings.Join(s.Advertised, ", "))
			}
		}
	}

	if len(hr.Recommendations) > 0 {
		fmt.Println("\nImprove quantum resilience")
		n := 0
		last := report.Priority("")
		for _, r := range hr.Recommendations {
			if r.Priority != last {
				fmt.Printf("  %s\n", strings.ToUpper(string(r.Priority)))
				last = r.Priority
			}
			n++
			fmt.Printf("  %2d. %s   [%s]\n", n, r.Title, strings.Join(r.Services, ", "))
			fmt.Printf("      %s\n", wrap(r.Why, 74, "      "))
			for _, st := range r.Steps {
				fmt.Printf("      - %s\n", wrap(st, 72, "        "))
			}
			for _, sn := range r.Snippets {
				fmt.Printf("      %s:\n", sn.Label)
				for _, line := range strings.Split(sn.Code, "\n") {
					fmt.Printf("          %s\n", line)
				}
			}
		}
	}

	fmt.Println("\npqscan checks key exchange, the part harvest-now-decrypt-later attacks: traffic")
	fmt.Println("recorded today with classical key exchange can be decrypted once a large quantum")
	fmt.Println("computer exists.")
	fmt.Println()
}

// trustLine states what backs every result: engine controls and the network path.
func trustLine(hr report.HostReport) string {
	passed := 0
	for _, c := range hr.Controls {
		if c.Pass {
			passed++
		}
	}
	line := fmt.Sprintf("Engine controls: %d/%d passed", passed, len(hr.Controls))
	switch p := hr.Path; {
	case p == nil:
		line += " · Network path: not verified (--reference <known ML-KEM server> to check)"
	case p.Error != "":
		line += fmt.Sprintf(" · Network path: reference %s unreachable", p.Reference)
	case p.Carried:
		line += fmt.Sprintf(" · Network path: carries ML-KEM (verified via %s)", p.Reference)
	default:
		line += fmt.Sprintf(" · Network path: STRIPS ML-KEM (%s read classical); classical results may be false negatives", p.Reference)
	}
	return line
}

func checkMark(outcome string) string {
	switch outcome {
	case "pq", "pass":
		return "✓"
	case "classical", "fail":
		return "✕"
	case "not_run":
		return "–"
	}
	return "?"
}

func list(svcs []report.ServiceReport) string {
	parts := make([]string, len(svcs))
	for i, s := range svcs {
		parts[i] = fmt.Sprintf("%s %d", s.Service, s.Port)
	}
	return strings.Join(parts, ", ")
}

func wrap(s string, width int, indent string) string {
	var b strings.Builder
	col := 0
	for i, w := range strings.Fields(s) {
		if col > 0 && col+1+len(w) > width {
			b.WriteString("\n" + indent)
			col = 0
		} else if i > 0 {
			b.WriteString(" ")
			col++
		}
		b.WriteString(w)
		col += len(w)
	}
	return b.String()
}
