// Command pqscan-web serves the PQC-readiness scanner as a web app: a static UI
// plus POST /api/scan. It runs as a single self-contained binary.
package main

import (
	"encoding/json"
	"flag"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	webui "pqscan/web"

	"pqscan/internal/probe"
	"pqscan/internal/safety"
	"pqscan/internal/services"
)

type scanRequest struct {
	Host     string   `json:"host"`
	Services []string `json:"services,omitempty"`
}

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	flag.Parse()

	if err := probe.SelfCalibrate(); err != nil {
		log.Fatalf("refusing to start: %v", err)
	}
	log.Print("self-calibration OK: engine detects X25519MLKEM768")

	limiter := safety.NewRateLimiter(30, time.Minute)

	mux := http.NewServeMux()
	mux.Handle("/", http.FileServerFS(webui.Files))
	mux.HandleFunc("/api/scan", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"POST only"}`, http.StatusMethodNotAllowed)
			return
		}
		if !limiter.Allow(clientIP(r)) {
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate limit exceeded, try again shortly"})
			return
		}
		var req scanRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		host, err := safety.Validate(req.Host)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		hr := services.Scan(host, services.Select(req.Services), probe.DefaultTimeout)
		writeJSON(w, http.StatusOK, hr)
	})

	log.Printf("pqscan-web listening on %s", *addr)
	srv := &http.Server{
		Addr:         *addr,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 60 * time.Second,
	}
	log.Fatal(srv.ListenAndServe())
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
