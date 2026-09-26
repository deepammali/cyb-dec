package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"pqscan/internal/cbom"
	"pqscan/internal/inspect"
	"pqscan/internal/observe"
)

var connLabel = map[observe.Class]string{
	observe.ClassPlaintext: "✕ Plaintext",
	observe.ClassClassical: "✕ Classical",
	observe.ClassUnknown:   "? Incomplete",
	observe.ClassPQ:        "✓ Post-quantum",
}

// runObserve implements "pqscan observe": data in transit, from captures.
func runObserve(args []string) int {
	fs := flag.NewFlagSet("observe", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "emit the JSON report")
	verbose := fs.Bool("v", false, "print the evidence for every connection, not only the ones that need action")
	keylog := fs.String("keylog", "", "SSLKEYLOGFILE-format key log: decrypts the TLS 1.3 sessions it has secrets for")
	cbomOut := fs.String("cbom", "", "also write a CycloneDX 1.6 CBOM to this file ('-' for stdout)")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: pqscan observe [flags] <capture.pcap|.pcapng>...\n\n"+
			"Reads packet captures (tcpdump -w, Wireshark) and reports how every connection\n"+
			"established its keys: TLS over TCP (including STARTTLS) and QUIC, SSH, IKEv2,\n"+
			"and WireGuard, with which clients never offer ML-KEM. Plaintext application\n"+
			"data, and TLS 1.3 data you hold keys for (--keylog), is searched for encrypted\n"+
			"artifacts. Nothing leaves this machine.\n\nflags:\n")
		fs.PrintDefaults()
	}
	fs.Parse(args)
	if fs.NArg() == 0 {
		fs.Usage()
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	o := observe.Options{}
	if *keylog != "" {
		f, err := os.Open(*keylog)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 2
		}
		o.KeyLog, err = observe.ParseKeyLog(f)
		f.Close()
		if err != nil {
			fmt.Fprintln(os.Stderr, "error: key log:", err)
			return 2
		}
	}
	start := time.Now()
	a := observe.New(ctx, o)
	for _, p := range fs.Args() {
		f, err := os.Open(p)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 2
		}
		err = a.Add(f)
		f.Close()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %s: %v\n", p, err)
			return 2
		}
	}
	r := a.Report()
	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	} else {
		printObserve(r, time.Since(start), *verbose)
	}
	if !writeCBOM(*cbomOut, func(b *cbom.Builder) { b.AddObserve(r) }) {
		return 2
	}
	return exitCode(r.Verdict)
}

func printObserve(r observe.Report, elapsed time.Duration, verbose bool) {
	span := ""
	if !r.First.IsZero() {
		span = fmt.Sprintf(" · %s – %s", r.First.Format("2006-01-02 15:04:05"), r.Last.Format("15:04:05 UTC"))
	}
	fmt.Printf("\npqscan observe · %d %s · %d packets%s · %.1f s\n", r.Captures, plural(r.Captures, "capture", "captures"), r.Packets, span, elapsed.Seconds())
	fmt.Printf("%s — %s\n", strings.ToUpper(r.Verdict.Label()), r.Headline)
	if k := r.KeyLog; k != nil {
		line := fmt.Sprintf("Key log: %d TLS 1.3 %s · %d %s decrypted", k.Sessions, plural(k.Sessions, "session", "sessions"), k.Decrypted, plural(k.Decrypted, "connection", "connections"))
		if k.NotDecrypted > 0 {
			line += fmt.Sprintf(" · %d not decrypted", k.NotDecrypted)
		}
		if k.TLS12Lines > 0 {
			line += fmt.Sprintf(" · %d TLS 1.2 %s ignored (TLS 1.3 only)", k.TLS12Lines, plural(k.TLS12Lines, "line", "lines"))
		}
		fmt.Println(line)
	}
	var counts []string
	for _, c := range observe.ClassOrder {
		if n := r.Counts[c]; n > 0 {
			counts = append(counts, fmt.Sprintf("%s %d", strings.TrimLeft(connLabel[c], "✕✓? "), n))
		}
	}
	if len(counts) > 0 {
		fmt.Println(strings.Join(counts, " · ") + fmt.Sprintf(" (of %d %s)", r.Connections, plural(r.Connections, "connection", "connections")))
		fmt.Printf("\n  %-16s %-15s %-44s %-24s %s\n", "RESULT", "PROTOCOL", "CLIENT → SERVER", "KEY EXCHANGE", "COUNT")
		for _, g := range r.Groups {
			dest := g.Server
			if g.ServerName != "" {
				dest += " (" + g.ServerName + ")"
			}
			fmt.Printf("  %-16s %-15s %-44s %-24s %d\n", connLabel[g.Class], clip(g.Protocol, 15), clip(g.ClientIP+" → "+dest, 44), clip(g.KeyExchange, 24), g.Count)
		}
		fmt.Println("\nEvidence")
		shown := 0
		for _, g := range r.Groups {
			if !verbose && g.Class == observe.ClassPQ && len(g.Findings) == 0 {
				continue
			}
			shown++
			fmt.Printf("  %s %s → %s — %s\n", g.Protocol, g.ClientIP, g.Label()[len(g.Protocol)+1:], wrap(g.Headline, 74, "    "))
			for _, e := range g.Evidence {
				fmt.Printf("    %-28s %s\n", e.Label+":", e.Value)
			}
			if g.Decryption != "" && g.Decryption != "decrypted" {
				fmt.Printf("    %-28s %s\n", "Key log:", g.Decryption)
			}
			for _, f := range g.Findings {
				fmt.Printf("    %-28s %s — %s (%s)\n", "In the traffic:", classLabel[f.Class], f.Format, f.Protection)
			}
			if g.Limits != "" {
				fmt.Printf("    Limits: %s\n", wrap(g.Limits, 70, "      "))
			}
		}
		if hidden := len(r.Groups) - shown; hidden > 0 {
			fmt.Printf("  (%d post-quantum %s not shown; -v shows their evidence)\n", hidden, plural(hidden, "group", "groups"))
		}
	}
	if len(r.Findings) > 0 {
		fmt.Printf("\nEncrypted artifacts in the traffic: %d\n", len(r.Findings))
		for _, f := range r.Findings {
			if f.Class == inspect.ClassExposed || f.Class == inspect.ClassWeak || verbose {
				fmt.Printf("  %-18s %-30s %s\n", classLabel[f.Class], clip(f.Format, 30), f.Path)
			}
		}
	}
	printRecommendations(r.Recommendations)
	if r.Unanalyzed > 0 {
		fmt.Printf("\nNot analyzed: %d TCP %s without a recognizable handshake or protocol (for example, captured after the handshake).\n", r.Unanalyzed, plural(r.Unanalyzed, "connection", "connections"))
	}
	fmt.Println()
}
