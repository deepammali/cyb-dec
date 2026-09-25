package services

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"pqscan/internal/report"
)

// CheckPath must report a path that carries ML-KEM when the reference supports
// it, and flag the path when a "known ML-KEM" reference reads classical.
func TestCheckPath(t *testing.T) {
	pq := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer pq.Close()
	classical := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	classical.TLS = &tls.Config{CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256}}
	classical.StartTLS()
	defer classical.Close()

	if pc := CheckPath(pq.Listener.Addr().String(), 3*time.Second); !pc.Carried || pc.Error != "" {
		t.Fatalf("ML-KEM reference: %+v, want carried", pc)
	}
	if pc := CheckPath(classical.Listener.Addr().String(), 3*time.Second); pc.Carried || pc.Error != "" {
		t.Fatalf("classical reference: %+v, want not carried", pc)
	}
	if pc := CheckPath("127.0.0.1:1", time.Second); pc.Error == "" {
		t.Fatalf("unreachable reference should report an error: %+v", pc)
	}
}

func TestPresetsCoverCatalog(t *testing.T) {
	seen := map[string]int{}
	for _, p := range Presets {
		if p.ID == "all" {
			if len(p.Services) != len(Catalog) {
				t.Fatalf("'all' has %d services, catalog has %d", len(p.Services), len(Catalog))
			}
			continue
		}
		for _, s := range p.Services {
			if _, ok := byName(strings.ToLower(s)); !ok {
				t.Errorf("preset %s names unknown service %s", p.ID, s)
			}
			seen[s]++
		}
	}
	for _, s := range Catalog {
		if seen[s.Name] != 1 {
			t.Errorf("service %s is in %d role presets, want exactly 1", s.Name, seen[s.Name])
		}
	}
}

func TestSelect(t *testing.T) {
	all, err := Select(nil)
	if err != nil || len(all) != len(Catalog) {
		t.Fatalf("empty selection = %d services, %v; want whole catalog", len(all), err)
	}
	if all[0].Name != "HTTPS" {
		t.Errorf("first service = %s, want HTTPS", all[0].Name)
	}
	mail, err := Select([]string{"mail"})
	if err != nil || len(mail) != 7 {
		t.Fatalf("mail preset = %d services, %v", len(mail), err)
	}
	mixed, err := Select([]string{"web,SSH"})
	if err != nil || len(mixed) != 2 || mixed[0].Name != "HTTPS" || mixed[1].Name != "SSH" {
		t.Fatalf("web,SSH = %+v, %v", mixed, err)
	}
	if _, err := Select([]string{"smpt"}); err == nil {
		t.Error("a typo should be reported, not silently dropped")
	}
}

func TestForPort(t *testing.T) {
	for _, p := range Protocols {
		if _, err := ForPort(p.ID, 2222); err != nil {
			t.Errorf("ForPort(%q): %v", p.ID, err)
		}
	}
	if _, err := ForPort("gopher", 70); err == nil {
		t.Error("unknown protocol should fail")
	}
}

func localPort(t *testing.T, addr string) int {
	_, p, _ := net.SplitHostPort(addr)
	n, _ := strconv.Atoi(p)
	return n
}

func TestScanStreamEmitsEachService(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer ts.Close()
	closed, _ := net.Listen("tcp", "127.0.0.1:0")
	closedPort := localPort(t, closed.Addr().String())
	closed.Close()

	auto, _ := ForPort("auto", localPort(t, ts.Listener.Addr().String()))
	svcs := []Service{
		{Name: "PQ", Port: localPort(t, ts.Listener.Addr().String()), Protocol: "tls"},
		{Name: "Closed", Port: closedPort, Protocol: "tls"},
		auto,
	}
	var emitted []report.ServiceReport
	hr := ScanStream(context.Background(), "127.0.0.1", svcs, 3*time.Second, report.Env{}, func(sr report.ServiceReport) {
		emitted = append(emitted, sr)
	})
	if len(emitted) != 3 || len(hr.Services) != 3 || hr.Partial {
		t.Fatalf("emitted %d, report %d, partial %v; want 3, 3, false", len(emitted), len(hr.Services), hr.Partial)
	}
	if hr.Services[0].State != report.StatePQ || hr.Services[1].State != report.StateClosed {
		t.Fatalf("states = %s, %s", hr.Services[0].State, hr.Services[1].State)
	}
	if a := hr.Services[2]; !a.Detected || a.State != report.StatePQ || a.Service != "TLS" {
		t.Fatalf("auto-detected service = %+v", a)
	}
}

func TestScanStreamStopsOnCancel(t *testing.T) {
	var accepted atomic.Int32
	silent, _ := net.Listen("tcp", "127.0.0.1:0")
	defer silent.Close()
	go func() {
		for {
			c, err := silent.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			go func() { time.Sleep(5 * time.Second); c.Close() }()
		}
	}()
	port := localPort(t, silent.Addr().String())
	var svcs []Service
	for i := 0; i < 20; i++ {
		svcs = append(svcs, Service{Name: "S" + strconv.Itoa(i), Port: port, Protocol: "tls"})
	}
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(300*time.Millisecond, cancel)
	start := time.Now()
	emits := 0
	hr := ScanStream(ctx, "127.0.0.1", svcs, 4*time.Second, report.Env{}, func(report.ServiceReport) { emits++ })
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("ScanStream returned after %v; want prompt return on cancel", d)
	}
	if !hr.Partial || emits != 0 || hr.Planned != 20 {
		t.Fatalf("partial=%v emits=%d planned=%d; want true, 0, 20", hr.Partial, emits, hr.Planned)
	}
	if n := accepted.Load(); n > 8 {
		t.Fatalf("%d probes launched after cancel; want at most the first wave of 8", n)
	}
}
