package report

import (
	"fmt"
	"sort"
	"strings"

	"pqscan/internal/probe"
)

// EstateReport rolls up many hosts scanned together.
type EstateReport struct {
	Targets         int              `json:"targets"`
	Hosts           []HostReport     `json:"hosts"`
	Verdict         Verdict          `json:"verdict"`
	Headline        string           `json:"headline"`
	Summary         EstateSummary    `json:"summary"`
	Partial         bool             `json:"partial,omitempty"`
	Recommendations []Recommendation `json:"recommendations"`
	Controls        []probe.Control  `json:"controls"`
	Path            *PathCheck       `json:"path,omitempty"`
}

// EstateSummary counts hosts by verdict and services by state across the estate.
type EstateSummary struct {
	HostsReady        int    `json:"hostsReady"`
	HostsNotReady     int    `json:"hostsNotReady"`
	HostsUndetermined int    `json:"hostsUndetermined"`
	Services          Counts `json:"services"`
	Plaintext         int    `json:"plaintext"`
}

// Estate rolls up host reports. targets is how many were planned.
func Estate(hosts []HostReport, targets int, env Env) EstateReport {
	er := EstateReport{Targets: targets, Hosts: hosts, Partial: len(hosts) < targets, Controls: env.Controls, Path: env.Path}
	for _, h := range hosts {
		switch h.Verdict {
		case Ready:
			er.Summary.HostsReady++
		case NotReady:
			er.Summary.HostsNotReady++
		default:
			er.Summary.HostsUndetermined++
		}
		c := &er.Summary.Services
		c.PQ += h.Counts.PQ
		c.Classical += h.Counts.Classical
		c.Closed += h.Counts.Closed
		c.NoResponse += h.Counts.NoResponse
		c.Error += h.Counts.Error
		for _, s := range h.Services {
			if isPlaintext(s.ServiceResult) {
				er.Summary.Plaintext++
			}
		}
	}
	s := er.Summary
	switch {
	case len(hosts) == 0:
		er.Verdict, er.Headline = Undetermined, "No hosts were scanned."
	case s.HostsNotReady > 0:
		er.Verdict = NotReady
		er.Headline = fmt.Sprintf("%d of %d %s services that aren't post-quantum.", s.HostsNotReady, len(hosts), plural(s.HostsNotReady, "hosts exposes", "hosts expose"))
		if len(hosts) == 1 {
			er.Headline = "The host exposes services that aren't post-quantum."
		}
	case s.HostsReady > 0:
		er.Verdict = Ready
		er.Headline = fmt.Sprintf("Every assessed host uses post-quantum key exchange (%d of %d; the rest couldn't be assessed).", s.HostsReady, len(hosts))
		if s.HostsUndetermined == 0 {
			er.Headline = fmt.Sprintf("All %d hosts use post-quantum key exchange on every exposed service.", len(hosts))
			if len(hosts) == 1 {
				er.Headline = "The host uses post-quantum key exchange on every exposed service."
			}
		}
	default:
		er.Verdict, er.Headline = Undetermined, "No scanned host exposed a service that could be assessed."
	}
	if s.Plaintext > 0 {
		er.Headline = strings.TrimSuffix(er.Headline, ".") + fmt.Sprintf("; %d %s plaintext.", s.Plaintext, plural(s.Plaintext, "service sends", "services send"))
	}
	er.Recommendations = aggregate(hosts)
	return er
}

// aggregate merges per-host recommendations by ID; affected services are
// qualified with their host.
func aggregate(hosts []HostReport) []Recommendation {
	out := []Recommendation{}
	index := map[string]int{}
	for _, h := range hosts {
		for _, r := range h.Recommendations {
			qualified := make([]string, len(r.Services))
			for i, s := range r.Services {
				qualified[i] = h.Host + " " + s
			}
			if i, ok := index[r.ID]; ok {
				out[i].Services = append(out[i].Services, qualified...)
				out[i].Snippets = mergeSnippets(out[i].Snippets, r.Snippets)
				continue
			}
			r.Services = qualified
			index[r.ID] = len(out)
			out = append(out, r)
		}
	}
	rankP := map[Priority]int{PriorityNow: 0, PriorityHarden: 1, PriorityPlan: 2}
	sort.SliceStable(out, func(i, j int) bool { return rankP[out[i].Priority] < rankP[out[j].Priority] })
	return out
}

func mergeSnippets(have, add []Snippet) []Snippet {
	seen := map[string]bool{}
	for _, s := range have {
		seen[s.Label] = true
	}
	for _, s := range add {
		if !seen[s.Label] {
			have = append(have, s)
			seen[s.Label] = true
		}
	}
	return have
}
