package report

import (
	"reflect"
	"strings"
	"testing"

	"pqscan/internal/probe"
)

func TestPoolMixed(t *testing.T) {
	r := tlsPQ("HTTPS", 443)
	r.OfferSamples = []string{"X25519MLKEM768", "X25519", "X25519MLKEM768"}
	sr := ForService(r, passing)
	if sr.State != StateClassical || sr.Verdict != NotReady || sr.Assessment.Confidence != ConfMixed {
		t.Fatalf("mixed pool: state %s verdict %s confidence %s", sr.State, sr.Verdict, sr.Assessment.Confidence)
	}
	if !strings.Contains(sr.Headline, "1 of 3 identical offers") {
		t.Fatalf("headline = %q", sr.Headline)
	}
	if ids := ids(Recommend([]ServiceReport{sr})); len(ids) == 0 || ids[0] != "mixed-fleet" {
		t.Fatalf("recommendations = %v, want mixed-fleet first", ids)
	}

	same := tlsPQ("HTTPS", 443)
	same.OfferSamples = []string{"X25519MLKEM768", "X25519MLKEM768", "error"}
	if sr := ForService(same, passing); sr.State != StatePQ || sr.Assessment.Confidence != ConfConfirmed {
		t.Fatalf("consistent samples: state %s confidence %s", sr.State, sr.Assessment.Confidence)
	}
}

func at(r probe.ServiceResult, addr string) probe.ServiceResult {
	r.Host, r.Address = "fleet.corp.local", addr
	return r
}

func TestMergeAddresses(t *testing.T) {
	agree := MergeAddresses([]ServiceReport{
		ForService(at(tlsPQ("HTTPS", 443), "10.0.0.1:443"), passing),
		ForService(at(tlsPQ("HTTPS", 443), "10.0.0.2:443"), passing),
	})
	if agree.State != StatePQ || len(agree.Addresses) != 2 || agree.PerAddress != nil || !strings.Contains(agree.Assessment.Limits, "all 2 addresses tested") {
		t.Fatalf("agreeing addresses: %+v", agree)
	}

	mixed := MergeAddresses([]ServiceReport{
		ForService(at(tlsPQ("HTTPS", 443), "10.0.0.1:443"), passing),
		ForService(at(tlsClassical("HTTPS", 443), "10.0.0.2:443"), passing),
		ForService(at(failed("HTTPS", 443, "timeout"), "10.0.0.3:443"), passing),
	})
	if mixed.State != StateClassical || mixed.Verdict != NotReady || mixed.Assessment.Confidence != ConfMixed || len(mixed.PerAddress) != 3 {
		t.Fatalf("mixed fleet: state %s verdict %s confidence %s per-address %d", mixed.State, mixed.Verdict, mixed.Assessment.Confidence, len(mixed.PerAddress))
	}
	if !strings.Contains(mixed.Headline, "1 of 3 addresses isn't") || !strings.Contains(mixed.Headline, "10.0.0.2:443") {
		t.Fatalf("headline = %q", mixed.Headline)
	}
	// The row's checks come from the weakest address, and say so.
	if c := mixed.Assessment.Checks; c[0].Name != "Every address" || c[1].Name != "Offer test (10.0.0.2:443)" {
		t.Fatalf("checks = %+v", c)
	}
}

func TestEdgeLimitAndRecommendation(t *testing.T) {
	r := tlsPQ("HTTPS", 443)
	r.Edge = &probe.Edge{Kind: "cdn", Name: "Cloudflare", Evidence: "cf-ray: abc"}
	sr := ForService(r, passing)
	if !strings.Contains(sr.Assessment.Limits, "TLS terminates at Cloudflare") {
		t.Fatalf("limits = %q", sr.Assessment.Limits)
	}
	found := false
	for _, rec := range Recommend([]ServiceReport{sr}) {
		if rec.ID == "behind-edge" {
			found = true
		}
	}
	if !found {
		t.Fatal("an edge should recommend measuring the hops behind it")
	}
}

func TestEstate(t *testing.T) {
	host := func(name string, rs ...probe.ServiceResult) HostReport {
		var svcs []ServiceReport
		for _, r := range rs {
			svcs = append(svcs, ForService(r, passing))
		}
		return Rollup(name, svcs, len(svcs), false, passing)
	}
	er := Estate([]HostReport{
		host("web1", tlsPQ("HTTPS", 443)),
		host("web2", tlsClassical("HTTPS", 443)),
		host("mail", failed("SMTP", 25, "no_starttls"), tlsClassical("IMAPS", 993)),
		host("dark", failed("HTTPS", 443, "refused")),
	}, 5, passing)

	if er.Verdict != NotReady || !er.Partial {
		t.Fatalf("verdict %s partial %v", er.Verdict, er.Partial)
	}
	want := EstateSummary{HostsReady: 1, HostsNotReady: 2, HostsUndetermined: 1,
		Services: Counts{PQ: 1, Classical: 2, Closed: 1, Error: 1}, Plaintext: 1}
	if er.Summary != want {
		t.Fatalf("summary = %+v, want %+v", er.Summary, want)
	}
	if er.Headline != "2 of 4 hosts expose services that aren't post-quantum; 1 service sends plaintext." {
		t.Fatalf("headline = %q", er.Headline)
	}
	var mlkem Recommendation
	for _, r := range er.Recommendations {
		if r.ID == "mlkem" {
			mlkem = r
		}
	}
	if !reflect.DeepEqual(mlkem.Services, []string{"web2 HTTPS:443", "mail IMAPS:993"}) {
		t.Fatalf("aggregated mlkem services = %v", mlkem.Services)
	}
	if er.Recommendations[0].Priority != PriorityNow {
		t.Fatalf("recommendations not priority-ordered: %v", ids(er.Recommendations))
	}
}
