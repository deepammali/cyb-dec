package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"os"
	"strings"
	"testing"
	"time"

	"pqscan/internal/probe"
	"pqscan/internal/safety"
	"pqscan/internal/services"
)

func TestEstateStream(t *testing.T) {
	pq := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer pq.Close()
	_, port, _ := net.SplitHostPort(pq.Listener.Addr().String())
	srv := testServer(t, false)

	body := `{"targets":"# two targets\n127.0.0.1:` + port + `\n127.0.0.1:1\n","protocol":"auto"}`
	resp, err := http.Post(srv.URL+"/api/estate/stream", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	count := map[string]int{}
	var done struct {
		Report struct {
			Targets int `json:"targets"`
			Summary struct {
				HostsReady        int `json:"hostsReady"`
				HostsUndetermined int `json:"hostsUndetermined"`
			} `json:"summary"`
		} `json:"report"`
	}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 1<<20), 4<<20)
	for sc.Scan() {
		var ev struct {
			Type string `json:"type"`
		}
		json.Unmarshal(sc.Bytes(), &ev)
		count[ev.Type]++
		if ev.Type == "done" {
			json.Unmarshal(sc.Bytes(), &done)
		}
	}
	if count["start"] != 1 || count["host-start"] != 2 || count["host-done"] != 2 || count["done"] != 1 {
		t.Fatalf("events = %v", count)
	}
	if done.Report.Targets != 2 || done.Report.Summary.HostsReady != 1 || done.Report.Summary.HostsUndetermined != 1 {
		t.Fatalf("estate = %+v", done.Report)
	}

	// A CIDR over the cap is refused before anything is probed.
	resp2, err := http.Post(srv.URL+"/api/estate/stream", "application/json", strings.NewReader(`{"targets":"10.0.0.0/24"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusBadRequest {
		t.Fatalf("oversized CIDR: status %d, want 400", resp2.StatusCode)
	}
}

func testServer(t *testing.T, publicOnly bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(newMux(config{publicOnly: publicOnly, timeout: 3 * time.Second, limiter: safety.NewRateLimiter(100, time.Minute),
		opts: services.Options{Timeout: 3 * time.Second}, maxHosts: 16, maxUpload: 1 << 20, controls: probe.RunControls()}))
	t.Cleanup(srv.Close)
	return srv
}

func TestCatalog(t *testing.T) {
	srv := testServer(t, false)
	resp, err := http.Get(srv.URL + "/api/catalog")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body struct {
		Services  []map[string]any `json:"services"`
		Presets   []map[string]any `json:"presets"`
		Protocols []map[string]any `json:"protocols"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if len(body.Services) != 19 || len(body.Presets) != 6 || len(body.Protocols) != 8 {
		t.Fatalf("catalog = %d services, %d presets, %d protocols", len(body.Services), len(body.Presets), len(body.Protocols))
	}
	if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'self'") {
		t.Fatalf("CSP = %q", csp)
	}
}

func TestScanStreamLocalTarget(t *testing.T) {
	pq := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer pq.Close()
	_, port, _ := net.SplitHostPort(pq.Listener.Addr().String())

	srv := testServer(t, false)
	resp, err := http.Post(srv.URL+"/api/scan/stream", "application/json",
		strings.NewReader(`{"host":"127.0.0.1:`+port+`","protocol":"auto"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var types []string
	var done struct {
		Report struct {
			Verdict  string `json:"verdict"`
			Services []struct {
				State      string `json:"state"`
				Detected   bool   `json:"detected"`
				Assessment struct {
					Confidence string `json:"confidence"`
				} `json:"assessment"`
			} `json:"services"`
			Controls []probe.Control `json:"controls"`
		} `json:"report"`
	}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var ev struct {
			Type string `json:"type"`
		}
		json.Unmarshal(sc.Bytes(), &ev)
		types = append(types, ev.Type)
		if ev.Type == "done" {
			json.Unmarshal(sc.Bytes(), &done)
		}
	}
	if strings.Join(types, ",") != "start,service,done" {
		t.Fatalf("event sequence = %v", types)
	}
	if done.Report.Verdict != "ready" || len(done.Report.Services) != 1 ||
		done.Report.Services[0].State != "pq" || !done.Report.Services[0].Detected {
		t.Fatalf("done report = %+v", done.Report)
	}
	if c := done.Report.Services[0].Assessment.Confidence; c != "confirmed" {
		t.Fatalf("confidence = %q, want confirmed (offer + forced checks agree)", c)
	}
	if len(done.Report.Controls) != 4 {
		t.Fatalf("report should carry the 4 engine controls, got %d", len(done.Report.Controls))
	}
}

func TestPublicOnlyRefusesPrivate(t *testing.T) {
	for _, tc := range []struct {
		publicOnly bool
		want       int
	}{{false, http.StatusOK}, {true, http.StatusBadRequest}} {
		srv := testServer(t, tc.publicOnly)
		resp, err := http.Post(srv.URL+"/api/scan", "application/json", strings.NewReader(`{"host":"127.0.0.1:1"}`))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != tc.want {
			t.Errorf("publicOnly=%v: status %d, want %d", tc.publicOnly, resp.StatusCode, tc.want)
		}
	}
}

func TestBadRequests(t *testing.T) {
	srv := testServer(t, false)
	for _, body := range []string{
		`not json`,
		`{"host":""}`,
		`{"host":"bad host"}`,
		`{"host":"example.com:99999"}`,
		`{"host":"127.0.0.1","services":["nope"]}`,
		`{"host":"127.0.0.1","protocol":"ssh"}`,
		`{"host":"no-such-host.invalid"}`,
	} {
		resp, err := http.Post(srv.URL+"/api/scan/stream", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		var e struct {
			Error string `json:"error"`
		}
		json.NewDecoder(resp.Body).Decode(&e)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest || e.Error == "" {
			t.Errorf("%s: status %d, error %q; want 400 with a message", body, resp.StatusCode, e.Error)
		}
	}
}

// A stopped scan's partial results get a real summary and recommendations.
func TestRollupForStoppedScan(t *testing.T) {
	srv := testServer(t, false)
	body := `{"host":"h","planned":19,"services":[{"service":"HTTPS","kind":"tls","port":443,"reachable":true,
		"negotiatedGroup":"X25519","groups":[{"group":"X25519MLKEM768","supported":false,"serverChose":"X25519"}],
		"forcedCheck":{"group":"X25519MLKEM768","refused":true}}]}`
	resp, err := http.Post(srv.URL+"/api/rollup", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var hr struct {
		Partial         bool `json:"partial"`
		Planned         int  `json:"planned"`
		Recommendations []struct {
			ID string `json:"id"`
		} `json:"recommendations"`
		Services []struct {
			State string `json:"state"`
		} `json:"services"`
	}
	json.NewDecoder(resp.Body).Decode(&hr)
	if !hr.Partial || hr.Planned != 19 || len(hr.Services) != 1 || hr.Services[0].State != "classical" ||
		len(hr.Recommendations) == 0 || hr.Recommendations[0].ID != "mlkem" {
		t.Fatalf("rollup = %+v", hr)
	}
}

func TestServesUI(t *testing.T) {
	srv := testServer(t, false)
	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET / = %d", resp.StatusCode)
	}
}

func upload(t *testing.T, url string, files map[string][]byte) *http.Response {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	for name, data := range files {
		h := textproto.MIMEHeader{}
		h.Set("Content-Disposition", `form-data; name="file"; filename="`+name+`"`)
		h.Set("Content-Type", "application/octet-stream")
		w, _ := mw.CreatePart(h)
		w.Write(data)
	}
	mw.Close()
	resp, err := http.Post(url, mw.FormDataContentType(), &body)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// Uploaded files are inspected in memory: folder paths are kept as labels and
// nothing lands in the temporary directory.
func TestInspectUpload(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	srv := testServer(t, false)
	age := []byte("age-encryption.org/v1\n-> X25519 dGVzdA\nYm9keQ\n--- bWFj\n\x00payload")
	resp := upload(t, srv.URL+"/api/inspect", map[string][]byte{
		"backup/secret.age": age,
		"notes.txt":         []byte("nothing here\n"),
	})
	defer resp.Body.Close()
	var r struct {
		Files    int    `json:"files"`
		Verdict  string `json:"verdict"`
		Findings []struct {
			Path  string `json:"path"`
			Class string `json:"class"`
		} `json:"findings"`
		Recommendations []struct {
			ID string `json:"id"`
		} `json:"recommendations"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 || r.Files != 2 || r.Verdict != "not_ready" || len(r.Findings) != 1 ||
		r.Findings[0].Path != "backup/secret.age" || r.Findings[0].Class != "exposed" || r.Recommendations[0].ID != "reencrypt-pq" {
		t.Fatalf("status %d, report %+v", resp.StatusCode, r)
	}
	if left, _ := os.ReadDir(tmp); len(left) != 0 {
		t.Fatalf("upload left files in TMPDIR: %v", left)
	}

	big := upload(t, srv.URL+"/api/inspect", map[string][]byte{"big.bin": make([]byte, 2<<20)})
	big.Body.Close()
	if big.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized upload: status %d, want 413", big.StatusCode)
	}
	none := upload(t, srv.URL+"/api/inspect", nil)
	none.Body.Close()
	if none.StatusCode != http.StatusBadRequest {
		t.Fatalf("empty upload: status %d, want 400", none.StatusCode)
	}
}
