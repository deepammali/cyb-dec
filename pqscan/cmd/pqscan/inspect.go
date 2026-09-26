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
)

var classLabel = map[inspect.Class]string{
	inspect.ClassExposed:   "✕ Exposed",
	inspect.ClassWeak:      "✕ Weak",
	inspect.ClassInventory: "~ Classical key",
	inspect.ClassSymmetric: "✓ Symmetric only",
	inspect.ClassPQ:        "✓ Post-quantum",
}

// runInspect implements "pqscan inspect": data at rest.
func runInspect(args []string) int {
	fs := flag.NewFlagSet("inspect", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "emit the JSON report")
	verbose := fs.Bool("v", false, "print the evidence for every finding, not only the ones that need action")
	maxFile := fs.Int64("max-file", inspect.DefaultMaxFileSize>>20, "MiB read from any one file or archive member; larger files are read head-only")
	maxDepth := fs.Int("max-depth", inspect.DefaultMaxDepth, "archive and mail nesting depth")
	cbomOut := fs.String("cbom", "", "also write a CycloneDX 1.6 CBOM to this file ('-' for stdout)")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: pqscan inspect [flags] <path>...\n\n"+
			"Finds encrypted data, keys, and certificates in files, archives (zip, tar, gzip,\n"+
			"bzip2), and mail (eml, mbox, Maildir), and reports which are exposed to\n"+
			"harvest-now-decrypt-later. Reads headers only: nothing is decrypted, no password\n"+
			"is needed, symbolic links are not followed, and nothing leaves this machine.\n\nflags:\n")
		fs.PrintDefaults()
	}
	fs.Parse(args)
	if fs.NArg() == 0 {
		fs.Usage()
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	start := time.Now()
	in := inspect.New(ctx, inspect.Options{MaxFileSize: *maxFile << 20, MaxDepth: *maxDepth}, nil)
	for _, p := range fs.Args() {
		in.Path(p)
	}
	r := in.Report()
	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	} else {
		printInspect(r, time.Since(start), *verbose)
	}
	if !writeCBOM(*cbomOut, func(b *cbom.Builder) { b.AddInspect(r) }) {
		return 2
	}
	return exitCode(r.Verdict)
}

func printInspect(r inspect.Report, elapsed time.Duration, verbose bool) {
	fmt.Printf("\npqscan inspect · %d %s · %d %s read (%s) · %.1f s\n", len(r.Roots), plural(len(r.Roots), "path", "paths"),
		r.Files, plural(r.Files, "file", "files"), size(r.Bytes), elapsed.Seconds())
	fmt.Printf("%s — %s\n", strings.ToUpper(r.Verdict.Label()), r.Headline)
	if r.Partial {
		fmt.Println("Stopped before every file was read.")
	}
	var counts []string
	for _, c := range inspect.ClassOrder {
		if n := r.Counts[c]; n > 0 {
			counts = append(counts, fmt.Sprintf("%s %d", strings.TrimLeft(classLabel[c], "✕✓~ "), n))
		}
	}
	if len(counts) > 0 {
		fmt.Println(strings.Join(counts, " · "))
		fmt.Printf("\n  %-18s %-34s %-34s %s\n", "RESULT", "FORMAT", "PROTECTION", "PATH")
		for _, f := range r.Findings {
			format := f.Format
			if f.Count > 1 {
				format = fmt.Sprintf("%s ×%d", format, f.Count)
			}
			fmt.Printf("  %-18s %-34s %-34s %s\n", classLabel[f.Class], clip(format, 34), clip(f.Protection, 34), f.Path)
		}
		fmt.Println("\nEvidence")
		shown := 0
		for _, f := range r.Findings {
			if !verbose && f.Class != inspect.ClassExposed && f.Class != inspect.ClassWeak {
				continue
			}
			shown++
			fmt.Printf("  %s — %s\n", f.Path, wrap(f.Headline, 74, "    "))
			for _, e := range f.Evidence {
				fmt.Printf("    %-22s %s\n", e.Label+":", e.Value)
			}
			fmt.Printf("    %-22s %s\n", "Confidence:", f.Confidence)
			if f.Limits != "" {
				fmt.Printf("    Limits: %s\n", wrap(f.Limits, 70, "      "))
			}
		}
		if hidden := len(r.Findings) - shown; hidden > 0 {
			fmt.Printf("  (%d more %s without action needed now; -v shows their evidence)\n", hidden, plural(hidden, "finding", "findings"))
		}
	}
	printRecommendations(r.Recommendations)
	if r.SkippedTotal > 0 {
		fmt.Printf("\nNot fully read: %d\n", r.SkippedTotal)
		for i, s := range r.Skipped {
			if i == 10 && !verbose {
				fmt.Printf("  … %d more (-v lists them)\n", r.SkippedTotal-10)
				break
			}
			fmt.Printf("  %s — %s\n", s.Path, s.Reason)
		}
	}
	fmt.Println()
}

func clip(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

func size(b int64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(b)/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(b)/(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(b)/(1<<10))
	}
	return fmt.Sprintf("%d B", b)
}
