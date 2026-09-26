// Command pqscan-web serves the PQC-readiness scanner as a web app: an embedded
// UI plus a JSON API. It runs as a single self-contained binary and makes no
// outbound requests other than the scans themselves, so it works offline.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	webui "pqscan/web"

	"pqscan/internal/cbom"
	"pqscan/internal/inspect"
	"pqscan/internal/observe"
	"pqscan/internal/probe"
	"pqscan/internal/report"
	"pqscan/internal/safety"
	"pqscan/internal/services"
)

type config struct {
	publicOnly bool          // refuse private/internal targets (for internet-facing deployments)
	timeout    time.Duration // per-probe timeout
	opts       services.Options
	maxHosts   int   // cap on an estate target list
	maxUpload  int64 // bytes accepted per /api/inspect request
	limiter    *safety.RateLimiter
	controls   []probe.Control // engine calibration, run once at startup
	reference  string          // known ML-KEM server for the network-path check; empty = off
	path       *pathCache
}

// pathCache holds the latest network-path check so every scan doesn't re-probe
// the reference server.
type pathCache struct {
	mu      sync.Mutex
	checked time.Time
	result  *report.PathCheck
}

const pathTTL = 5 * time.Minute

func (cfg config) env() report.Env {
	env := report.Env{Controls: cfg.controls}
	if cfg.reference == "" || cfg.path == nil {
		return env
	}
	cfg.path.mu.Lock()
	defer cfg.path.mu.Unlock()
	if cfg.path.result == nil || time.Since(cfg.path.checked) > pathTTL {
		cfg.path.result = services.CheckPath(cfg.reference, cfg.timeout)
		cfg.path.checked = time.Now()
	}
	env.Path = cfg.path.result
	return env
}

type scanRequest struct {
	Host     string   `json:"host"`
	Services []string `json:"services,omitempty"` // service names or preset IDs
	Protocol string   `json:"protocol,omitempty"` // for host:port targets; default auto
}

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	publicOnly := flag.Bool("public-only", false, "refuse private, loopback, and link-local targets (use when exposing this server to the internet)")
	timeout := flag.Duration("timeout", probe.DefaultTimeout, "per-probe timeout")
	reference := flag.String("reference", "", "host[:port] of a server known to support ML-KEM, used to verify this scanner's network path (off by default: no outside contact)")
	maxHosts := flag.Int("max-hosts", 256, "cap on hosts an estate target list (CIDRs included) may expand to")
	samples := flag.Int("samples", services.DefaultSamples, "repeat the decisive ML-KEM offer this many times per TLS service (reveals mixed pools)")
	maxAddrs := flag.Int("max-addresses", services.DefaultMaxAddresses, "probe up to this many addresses per name (reveals mixed fleets)")
	maxUpload := flag.Int64("max-upload", 200, "MB accepted per file or capture upload (processed in memory, never written to disk)")
	flag.Parse()

	controls := probe.RunControls()
	for _, c := range controls {
		log.Printf("engine control %-22s pass=%v  got: %s", c.Name, c.Pass, c.Got)
	}
	if !probe.ControlsPassed(controls) {
		log.Fatal("refusing to start: engine controls failed, so results would not be trustworthy")
	}
	if *publicOnly {
		log.Print("--public-only: private and internal targets will be refused")
	}
	if *reference != "" {
		log.Printf("network-path check enabled against %s", *reference)
	}

	srv := &http.Server{
		Addr: *addr,
		Handler: newMux(config{
			publicOnly: *publicOnly, timeout: *timeout, limiter: safety.NewRateLimiter(30, time.Minute),
			opts:     services.Options{Timeout: *timeout, Samples: *samples, MaxAddresses: *maxAddrs},
			maxHosts: *maxHosts, maxUpload: *maxUpload << 20, controls: controls, reference: *reference, path: &pathCache{},
		}),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      90 * time.Second,
	}
	log.Printf("pqscan-web listening on %s", *addr)
	log.Fatal(srv.ListenAndServe())
}

func newMux(cfg config) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /", http.FileServerFS(webui.Files))

	mux.HandleFunc("GET /api/catalog", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"services":   services.Catalog,
			"presets":    services.Presets,
			"protocols":  services.Protocols,
			"publicOnly": cfg.publicOnly,
			"controls":   cfg.controls,
			"reference":  cfg.reference,
			"maxHosts":   cfg.maxHosts,
			"maxUpload":  cfg.maxUpload,
		})
	})

	// Inspect uploaded files. Parts are read one at a time into memory and
	// parsed there: nothing is written to disk (ParseMultipartForm would spill
	// large uploads to temporary files, so it is never used), and the server
	// never reads its own filesystem by path.
	mux.HandleFunc("POST /api/inspect", func(w http.ResponseWriter, r *http.Request) {
		if !cfg.limiter.Allow(clientIP(r)) {
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate limit exceeded, try again shortly"})
			return
		}
		rc := http.NewResponseController(w)
		rc.SetReadDeadline(time.Now().Add(30 * time.Minute)) // large uploads over slow links
		rc.SetWriteDeadline(time.Now().Add(35 * time.Minute))
		r.Body = http.MaxBytesReader(w, r.Body, cfg.maxUpload)
		mr, err := r.MultipartReader()
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "expected a multipart/form-data upload"})
			return
		}
		in := inspect.New(r.Context(), inspect.Options{MaxFileSize: cfg.maxUpload}, nil)
		files := 0
		for {
			part, err := mr.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				uploadError(w, err, cfg.maxUpload)
				return
			}
			if part.FormName() != "file" {
				continue
			}
			data, err := io.ReadAll(part)
			if err != nil {
				uploadError(w, err, cfg.maxUpload)
				return
			}
			in.Bytes(uploadName(part.Header.Get("Content-Disposition"), files), data)
			files++
		}
		if files == 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no files were uploaded"})
			return
		}
		writeJSON(w, http.StatusOK, in.Report())
	})

	mux.HandleFunc("POST /api/observe", observeHandler(cfg))

	// CBOM: turn a report the page already has into CycloneDX 1.6, without rescanning.
	mux.HandleFunc("POST /api/cbom", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Kind   string          `json:"kind"` // host, estate, files, capture
			Report json.RawMessage `json:"report"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<20)).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		b := cbom.NewBuilder()
		var err error
		switch req.Kind {
		case "host":
			var hr report.HostReport
			if err = json.Unmarshal(req.Report, &hr); err == nil {
				b.AddHost(hr)
			}
		case "estate":
			var er report.EstateReport
			if err = json.Unmarshal(req.Report, &er); err == nil {
				b.AddEstate(er)
			}
		case "files":
			var ir inspect.Report
			if err = json.Unmarshal(req.Report, &ir); err == nil {
				b.AddInspect(ir)
			}
		case "capture":
			var or observe.Report
			if err = json.Unmarshal(req.Report, &or); err == nil {
				b.AddObserve(or)
			}
		default:
			err = errors.New("kind must be host, estate, files, or capture")
		}
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "cbom: " + err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, b.BOM())
	})

	mux.HandleFunc("POST /api/scan", func(w http.ResponseWriter, r *http.Request) {
		host, svcs, ok := cfg.admit(w, r)
		if !ok {
			return
		}
		writeJSON(w, http.StatusOK, services.ScanStream(r.Context(), host, svcs, cfg.opts, cfg.env(), nil))
	})

	// Estate stream: "start" (targets), then per host "host-start", "service"
	// events, and "host-done", then "done" with the estate report.
	mux.HandleFunc("POST /api/estate/stream", func(w http.ResponseWriter, r *http.Request) {
		if !cfg.limiter.Allow(clientIP(r)) {
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate limit exceeded, try again shortly"})
			return
		}
		var req struct {
			Targets  string   `json:"targets"` // one host, host:port, URL, or CIDR per line
			Services []string `json:"services,omitempty"`
			Protocol string   `json:"protocol,omitempty"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10)).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		targets, err := safety.ParseTargets(strings.NewReader(req.Targets), cfg.maxHosts)
		if err == nil && cfg.publicOnly {
			for _, t := range targets {
				if err = safety.ValidatePublic(t.Host); err != nil {
					break
				}
			}
		}
		var scope []services.Service
		if err == nil {
			scope, err = services.Select(req.Services)
		}
		if err == nil && req.Protocol != "" {
			_, err = services.ForPort(req.Protocol, 1)
		}
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		send, rc := ndjson(w)
		rc.SetWriteDeadline(time.Now().Add(time.Hour))
		env := cfg.env()
		send(map[string]any{"type": "start", "targets": targets, "services": scope, "startedAt": time.Now().UTC(),
			"controls": env.Controls, "path": env.Path})
		er := services.ScanEstate(r.Context(), targets, scope, req.Protocol, cfg.opts, env, func(ev services.EstateEvent) { send(ev) })
		if r.Context().Err() == nil {
			send(map[string]any{"type": "done", "report": er})
		}
	})

	// Estate rollup for a stopped estate scan: the hosts that finished.
	mux.HandleFunc("POST /api/estate/rollup", func(w http.ResponseWriter, r *http.Request) {
		if !cfg.limiter.Allow(clientIP(r)) {
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate limit exceeded, try again shortly"})
			return
		}
		var req struct {
			Targets int                 `json:"targets"`
			Hosts   []report.HostReport `json:"hosts"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<20)).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		writeJSON(w, http.StatusOK, report.Estate(req.Hosts, req.Targets, cfg.env()))
	})

	// NDJSON stream: one "start" event, one "service" event per finished probe,
	// then "done" with the host report. Closing the connection stops the scan.
	mux.HandleFunc("POST /api/scan/stream", func(w http.ResponseWriter, r *http.Request) {
		host, svcs, ok := cfg.admit(w, r)
		if !ok {
			return
		}
		send, rc := ndjson(w)
		rc.SetWriteDeadline(time.Now().Add(5 * time.Minute))
		env := cfg.env()
		send(map[string]any{"type": "start", "host": host, "services": svcs, "startedAt": time.Now().UTC(),
			"controls": env.Controls, "path": env.Path})
		hr := services.ScanStream(r.Context(), host, svcs, cfg.opts, env, func(sr report.ServiceReport) {
			send(map[string]any{"type": "service", "service": sr})
		})
		if r.Context().Err() == nil {
			send(map[string]any{"type": "done", "report": hr})
		}
	})

	// Rollup for a stopped scan: the stream closes before "done", so the UI sends
	// back the service reports it received and gets the summary and
	// recommendations for exactly those. It probes nothing.
	mux.HandleFunc("POST /api/rollup", func(w http.ResponseWriter, r *http.Request) {
		if !cfg.limiter.Allow(clientIP(r)) {
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate limit exceeded, try again shortly"})
			return
		}
		var req struct {
			Host     string                 `json:"host"`
			Planned  int                    `json:"planned"`
			Services []report.ServiceReport `json:"services"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		env := cfg.env()
		svcs := make([]report.ServiceReport, 0, len(req.Services))
		for _, s := range req.Services {
			svcs = append(svcs, report.ForService(s.ServiceResult, env))
		}
		writeJSON(w, http.StatusOK, report.Rollup(req.Host, svcs, req.Planned, len(svcs) < req.Planned, env))
	})

	return securityHeaders(mux)
}

// observeHandler analyzes uploaded captures. The capture streams through the
// analyzer part by part, so only per-connection handshake and payload buffers
// are held, not the file; a key log part (optional) decrypts TLS 1.3 sessions.
func observeHandler(cfg config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !cfg.limiter.Allow(clientIP(r)) {
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate limit exceeded, try again shortly"})
			return
		}
		rc := http.NewResponseController(w)
		rc.SetReadDeadline(time.Now().Add(30 * time.Minute))
		rc.SetWriteDeadline(time.Now().Add(35 * time.Minute))
		r.Body = http.MaxBytesReader(w, r.Body, cfg.maxUpload)
		mr, err := r.MultipartReader()
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "expected a multipart/form-data upload"})
			return
		}
		a := observe.New(r.Context(), observe.Options{})
		captures := 0
		for {
			part, err := mr.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				uploadError(w, err, cfg.maxUpload)
				return
			}
			switch part.FormName() {
			case "capture":
				if err := a.Add(part); err != nil {
					var tooBig *http.MaxBytesError
					if errors.As(err, &tooBig) {
						uploadError(w, err, cfg.maxUpload)
						return
					}
					writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("%s: %v", uploadName(part.Header.Get("Content-Disposition"), captures), err)})
					return
				}
				captures++
			case "keylog":
				k, err := observe.ParseKeyLog(io.LimitReader(part, 64<<20))
				if err != nil {
					writeJSON(w, http.StatusBadRequest, map[string]string{"error": "key log: " + err.Error()})
					return
				}
				a.SetKeyLog(k)
			}
		}
		if captures == 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no capture was uploaded"})
			return
		}
		writeJSON(w, http.StatusOK, a.Report())
	}
}

func uploadError(w http.ResponseWriter, err error, limit int64) {
	var tooBig *http.MaxBytesError
	if errors.As(err, &tooBig) {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": fmt.Sprintf("upload exceeds %d MB; inspect fewer files at once or raise --max-upload", limit>>20)})
		return
	}
	writeJSON(w, http.StatusBadRequest, map[string]string{"error": "upload failed: " + err.Error()})
}

// uploadName is the display name of an uploaded file: the browser's relative
// path (folder uploads keep their structure). It is a label only, never a path
// on this server.
func uploadName(disposition string, n int) string {
	name := ""
	if _, params, err := mime.ParseMediaType(disposition); err == nil {
		name = params["filename"]
	}
	name = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, name)
	if len(name) > 512 {
		name = name[len(name)-512:]
	}
	if name == "" {
		name = fmt.Sprintf("upload %d", n+1)
	}
	return name
}

// ndjson prepares a streaming NDJSON response; send writes one event and flushes.
func ndjson(w http.ResponseWriter) (func(any), *http.ResponseController) {
	rc := http.NewResponseController(w)
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	enc := json.NewEncoder(w)
	return func(v any) {
		enc.Encode(v)
		rc.Flush()
	}, rc
}

// admit rate-limits and validates a scan request, writing the error response
// itself when it refuses.
func (cfg config) admit(w http.ResponseWriter, r *http.Request) (string, []services.Service, bool) {
	if !cfg.limiter.Allow(clientIP(r)) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate limit exceeded, try again shortly"})
		return "", nil, false
	}
	var req scanRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return "", nil, false
	}
	host, svcs, err := cfg.plan(req)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return "", nil, false
	}
	return host, svcs, true
}

func (cfg config) plan(req scanRequest) (string, []services.Service, error) {
	host, port, err := safety.ParseTarget(req.Host)
	if err != nil {
		return "", nil, err
	}
	if cfg.publicOnly {
		err = safety.ValidatePublic(host)
	} else {
		err = safety.Resolve(host)
	}
	if err != nil {
		return "", nil, err
	}
	if port > 0 {
		s, err := services.ForPort(req.Protocol, port)
		if err != nil {
			return "", nil, err
		}
		return host, []services.Service{s}, nil
	}
	if req.Protocol != "" && !strings.EqualFold(req.Protocol, "auto") {
		return "", nil, errors.New("a protocol applies only to a host:port target")
	}
	svcs, err := services.Select(req.Services)
	return host, svcs, err
}

// securityHeaders pins the page to its own origin: the UI loads nothing from
// anywhere else, which is also what keeps it working offline.
func securityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		h.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.TrimSpace(strings.Split(xff, ",")[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
