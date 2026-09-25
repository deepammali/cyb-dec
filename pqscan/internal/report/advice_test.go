package report

import (
	"reflect"
	"sort"
	"testing"

	"pqscan/internal/probe"
)

func ssh(banner string, pq bool, advertised ...string) probe.ServiceResult {
	r := probe.ServiceResult{Service: "SSH", Kind: "ssh", Port: 22, Reachable: true, Banner: banner, Advertised: advertised}
	for _, k := range advertised {
		if k == "mlkem768x25519-sha256" || k == "sntrup761x25519-sha512@openssh.com" {
			r.Groups = append(r.Groups, probe.GroupResult{Group: k, Supported: true})
			if pq && r.BestPQGroup == "" {
				r.BestPQGroup = k
			}
		}
	}
	r.PQKeyExchange = pq
	return r
}

func ids(recs []Recommendation) []string {
	var out []string
	for _, r := range recs {
		out = append(out, r.ID)
	}
	return out
}

func recommend(rs ...probe.ServiceResult) []Recommendation {
	var svcs []ServiceReport
	for _, r := range rs {
		svcs = append(svcs, ForService(r, passing))
	}
	return Recommend(svcs)
}

func TestRecommendRules(t *testing.T) {
	pqAll := tlsPQ("HTTPS", 443)
	pqAll.Groups = append(pqAll.Groups, probe.GroupResult{Group: "SecP384r1MLKEM1024", Supported: true})

	notPreferred := tlsClassical("HTTPS", 443)
	notPreferred.Forced = &probe.ForcedCheck{Completed: true}

	partial := tlsClassical("HTTPS", 443)
	partial.PQKeyExchange, partial.BestPQGroup = true, "SecP256r1MLKEM768"
	partial.Groups = append(partial.Groups, probe.GroupResult{Group: "SecP256r1MLKEM768", Supported: true})

	inconsistent := pqAll
	inconsistent.Forced = &probe.ForcedCheck{Refused: true}

	withCert := tlsClassical("HTTPS", 443)
	withCert.CertSigAlg = "SHA256-RSA"

	aes128 := tlsPQ("HTTPS", 443)
	aes128.Groups = pqAll.Groups
	aes128.ServerCipher = "TLS_AES_128_GCM_SHA256"

	tls12 := tlsClassical("HTTPS", 443)
	tls12.TLSVersion, tls12.NegotiatedGroup = "TLS 1.2", "none (TLS 1.2 handshake)"

	legacy := tlsClassical("HTTPS", 443)
	legacy.BestPQGroup = "X25519Kyber768Draft00 (legacy)"

	cases := []struct {
		name string
		in   []probe.ServiceResult
		want []string
	}{
		{"classical TLS", []probe.ServiceResult{tlsClassical("HTTPS", 443)}, []string{"mlkem"}},
		{"supported, not preferred", []probe.ServiceResult{notPreferred}, []string{"prefer-mlkem"}},
		{"P-256 hybrid only", []probe.ServiceResult{partial}, []string{"add-x25519mlkem768", "cnsa-mlkem1024"}},
		{"checks disagree", []probe.ServiceResult{inconsistent}, []string{"inconsistent"}},
		{"classical TLS with cert", []probe.ServiceResult{withCert}, []string{"mlkem", "mldsa"}},
		{"TLS 1.2 only", []probe.ServiceResult{tls12}, []string{"tls13", "mlkem"}},
		{"legacy Kyber only", []probe.ServiceResult{legacy}, []string{"legacy-kyber"}},
		{"plaintext SMTP", []probe.ServiceResult{failed("SMTP", 25, "no_starttls")}, []string{"plaintext"}},
		{"PQ without ML-KEM-1024", []probe.ServiceResult{tlsPQ("HTTPS", 443)}, []string{"cnsa-mlkem1024"}},
		{"PQ with ML-KEM-1024", []probe.ServiceResult{pqAll}, nil},
		{"server prefers AES-128", []probe.ServiceResult{aes128}, []string{"cnsa-aes256"}},
		{"OpenSSH 8.9 classical", []probe.ServiceResult{ssh("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3", false, "curve25519-sha256")}, []string{"ssh-upgrade"}},
		{"OpenSSH 9.6 classical", []probe.ServiceResult{ssh("SSH-2.0-OpenSSH_9.6", false, "curve25519-sha256")}, []string{"ssh-restore"}},
		{"Dropbear classical", []probe.ServiceResult{ssh("SSH-2.0-dropbear_2022.83", false, "curve25519-sha256")}, []string{"ssh-other"}},
		{"sntrup only", []probe.ServiceResult{ssh("SSH-2.0-OpenSSH_9.6", true, "sntrup761x25519-sha512@openssh.com", "curve25519-sha256")}, []string{"ssh-mlkem"}},
		{"OpenSSH 10 ML-KEM", []probe.ServiceResult{ssh("SSH-2.0-OpenSSH_10.0", true, "mlkem768x25519-sha256", "curve25519-sha256")}, nil},
		{"closed and filtered", []probe.ServiceResult{failed("SMTPS", 465, "refused"), failed("Redis", 6379, "timeout")}, nil},
	}
	for _, tc := range cases {
		got := ids(recommend(tc.in...))
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestRecommendPriorityOrderAndServices(t *testing.T) {
	withCert := tlsClassical("HTTPS", 443)
	withCert.CertSigAlg = "SHA256-RSA"
	recs := recommend(
		withCert,
		tlsClassical("IMAPS", 993),
		ssh("SSH-2.0-OpenSSH_9.6", true, "sntrup761x25519-sha512@openssh.com"),
		failed("SMTP", 25, "no_starttls"),
	)
	rank := map[Priority]int{PriorityNow: 0, PriorityHarden: 1, PriorityPlan: 2}
	if !sort.SliceIsSorted(recs, func(i, j int) bool { return rank[recs[i].Priority] < rank[recs[j].Priority] }) {
		t.Fatalf("not ordered by priority: %v", ids(recs))
	}
	for _, r := range recs {
		if r.ID == "mlkem" && !reflect.DeepEqual(r.Services, []string{"HTTPS:443", "IMAPS:993"}) {
			t.Errorf("mlkem services = %v", r.Services)
		}
		if r.ID == "mlkem" && len(r.Snippets) == 0 {
			t.Error("mlkem should carry config snippets")
		}
	}
}

func TestOpenSSHVersion(t *testing.T) {
	cases := map[string][3]int{
		"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10": {8, 9, 1},
		"SSH-2.0-OpenSSH_9.6":                      {9, 6, 1},
		"SSH-2.0-OpenSSH_10.0":                     {10, 0, 1},
		"SSH-2.0-OpenSSH_for_Windows_9.5":          {9, 5, 1},
		"SSH-2.0-dropbear_2022.83":                 {0, 0, 0},
	}
	for banner, want := range cases {
		maj, min, ok := opensshVersion(banner)
		got := [3]int{maj, min, 0}
		if ok {
			got[2] = 1
		}
		if got != want {
			t.Errorf("opensshVersion(%q) = %v, want %v", banner, got, want)
		}
	}
}
