package probe

import (
	"bufio"
	"net"
	"net/http"
	"strings"
	"time"
)

// Edge says that TLS terminated at an intermediary, so the origin server and
// the hops behind it are separate connections this probe never measured.
type Edge struct {
	Kind     string `json:"kind"` // "cdn" or "proxy"
	Name     string `json:"name"`
	Evidence string `json:"evidence"`
}

// edgeRules map response headers to known intermediaries. A header's presence is
// the evidence; no rule relies on guessing from a bare Server value like nginx.
var edgeRules = []struct {
	kind, name string
	match      func(h http.Header) string
}{
	{"cdn", "Cloudflare", func(h http.Header) string {
		if v := h.Get("Cf-Ray"); v != "" {
			return "cf-ray: " + v
		}
		return serverIs(h, "cloudflare")
	}},
	{"cdn", "Amazon CloudFront", func(h http.Header) string {
		if v := h.Get("X-Amz-Cf-Id"); v != "" {
			return "x-amz-cf-id present"
		}
		return viaHas(h, "cloudfront")
	}},
	{"cdn", "Akamai", func(h http.Header) string { return serverIs(h, "akamaighost") }},
	{"cdn", "Fastly", func(h http.Header) string {
		if v := h.Get("X-Served-By"); strings.Contains(strings.ToLower(v), "cache-") {
			return "x-served-by: " + v
		}
		return ""
	}},
	{"cdn", "Azure Front Door", func(h http.Header) string {
		if h.Get("X-Azure-Ref") != "" {
			return "x-azure-ref present"
		}
		return ""
	}},
	{"proxy", "Google Front End", func(h http.Header) string { return viaHas(h, "google") }},
	{"proxy", "AWS load balancer", func(h http.Header) string { return serverIs(h, "awselb") }},
	{"proxy", "Envoy", func(h http.Header) string {
		if s := serverIs(h, "envoy"); s != "" {
			return s
		}
		if h.Get("X-Envoy-Upstream-Service-Time") != "" {
			return "x-envoy-upstream-service-time present"
		}
		return ""
	}},
	{"proxy", "HTTP proxy", func(h http.Header) string {
		if v := h.Get("Via"); v != "" {
			return "via: " + v
		}
		return ""
	}},
	{"proxy", "caching proxy", func(h http.Header) string {
		if v := h.Get("X-Cache"); v != "" {
			return "x-cache: " + v
		}
		return ""
	}},
}

func serverIs(h http.Header, token string) string {
	if v := h.Get("Server"); strings.Contains(strings.ToLower(v), token) {
		return "server: " + v
	}
	return ""
}

func viaHas(h http.Header, token string) string {
	if v := h.Get("Via"); strings.Contains(strings.ToLower(v), token) {
		return "via: " + v
	}
	return ""
}

// detectEdge sends one HEAD request over an established TLS connection and
// looks for headers that intermediaries add. It returns nil when none appear,
// which doesn't prove the absence of one (a proxy can hide itself).
func detectEdge(conn net.Conn, host string, timeout time.Duration) *Edge {
	conn.SetDeadline(time.Now().Add(timeout))
	req, err := http.NewRequest(http.MethodHead, "https://"+host+"/", nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "pqscan")
	req.Close = true
	if err := req.Write(conn); err != nil {
		return nil
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return nil
	}
	resp.Body.Close()
	return edgeFromHeaders(resp.Header)
}

func edgeFromHeaders(h http.Header) *Edge {
	for _, r := range edgeRules {
		if ev := r.match(h); ev != "" {
			return &Edge{Kind: r.kind, Name: r.name, Evidence: ev}
		}
	}
	return nil
}
