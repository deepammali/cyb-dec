package report

import (
	"fmt"
	"strings"
)

// outcomeKey identifies what a client would experience at one address; two
// addresses agree when their keys match.
func outcomeKey(s ServiceReport) string {
	return fmt.Sprintf("%s|%s|%s|%s", s.State, s.NegotiatedGroup, s.BestPQGroup, s.ErrorKind)
}

// rank orders states from worst for a client to least informative, so a merged
// row shows the weakest reachable configuration.
func rank(s ServiceReport) int {
	switch {
	case isPlaintext(s.ServiceResult):
		return 0
	case s.State == StateClassical:
		return 1
	case s.State == StatePQ:
		return 2
	case s.State == StateError:
		return 3
	case s.State == StateNoResponse:
		return 4
	}
	return 5
}

// MergeAddresses combines one service's results from every address a name
// resolved to. When they agree, the result is kept and every address is listed.
// When they disagree, the weakest reachable configuration becomes the row's
// result and each address's outcome is listed: some clients get it.
func MergeAddresses(parts []ServiceReport) ServiceReport {
	if len(parts) == 0 {
		return ServiceReport{}
	}
	addrs := make([]string, len(parts))
	for i, p := range parts {
		addrs[i] = orAddr(p.ServiceResult)
	}
	if len(parts) == 1 {
		return parts[0]
	}

	agree := true
	for _, p := range parts[1:] {
		if outcomeKey(p) != outcomeKey(parts[0]) {
			agree = false
			break
		}
	}
	if agree {
		m := parts[0]
		m.Addresses = addrs
		m.Assessment.Checks = append([]Check{{Name: "Every address", Outcome: "pass",
			Detail: fmt.Sprintf("All %d addresses tested for %s gave the same result: %s.", len(parts), m.Host, strings.Join(addrs, ", "))}}, m.Assessment.Checks...)
		m.Assessment.Limits = strings.Replace(m.Assessment.Limits, "Valid for "+addrs[0], fmt.Sprintf("Valid for all %d addresses tested (%s)", len(parts), strings.Join(addrs, ", ")), 1)
		return m
	}

	worst := parts[0]
	for _, p := range parts[1:] {
		if rank(p) < rank(worst) {
			worst = p
		}
	}
	m := worst
	m.Addresses = addrs
	m.PerAddress = make([]AddressOutcome, len(parts))
	var pq, notPQ []string
	for i, p := range parts {
		m.PerAddress[i] = AddressOutcome{Address: addrs[i], State: p.State, NegotiatedGroup: p.NegotiatedGroup, Headline: p.Headline}
		switch {
		case p.State == StatePQ:
			pq = append(pq, addrs[i])
		case p.State == StateClassical || isPlaintext(p.ServiceResult):
			notPQ = append(notPQ, addrs[i])
		}
	}
	// The row's own checks come from the weakest address; name it on each.
	worstAddr := orAddr(worst.ServiceResult)
	checks := []Check{{Name: "Every address", Outcome: "fail",
		Detail: fmt.Sprintf("The %d addresses tested for %s disagree; each is listed below. The checks that follow are for %s.", len(parts), m.Host, worstAddr)}}
	for _, c := range m.Assessment.Checks {
		if c.Name != "Engine controls" && c.Name != "Network path" && !strings.Contains(c.Detail, worstAddr) {
			c.Name += " (" + worstAddr + ")"
		}
		checks = append(checks, c)
	}
	m.Assessment.Checks = checks
	if len(pq) > 0 && len(notPQ) > 0 {
		m.Assessment.Confidence = ConfMixed
		m.Assessment.Summary = "Mixed fleet: addresses behind this name are configured differently."
		m.Assessment.Question = qFN
		m.Assessment.Answer = fmt.Sprintf("No. Each address was checked on its own. Post-quantum: %s. Not post-quantum: %s. Clients whose DNS answer points at an address that isn't post-quantum get classical key exchange.", strings.Join(pq, ", "), strings.Join(notPQ, ", "))
		verb := "aren't"
		if len(notPQ) == 1 {
			verb = "isn't"
		}
		m.Headline = fmt.Sprintf("Mixed fleet: %d of %d addresses %s post-quantum (%s).", len(notPQ), len(parts), verb, strings.Join(notPQ, ", "))
		m.Verdict = NotReady
	} else {
		m.Headline = fmt.Sprintf("Addresses disagree: %s", worst.Headline)
	}
	m.Assessment.Limits = fmt.Sprintf("Covers %s as reached from this scanner at scan time.", strings.Join(addrs, ", "))
	return m
}
