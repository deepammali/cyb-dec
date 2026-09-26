package services

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"pqscan/internal/probe"
	"pqscan/internal/report"
	"pqscan/internal/safety"
)

// Options control how a scan probes.
type Options struct {
	Timeout      time.Duration   // per probe
	Samples      int             // decisive-offer repetitions per TLS service (reveals mixed pools)
	MaxAddresses int             // addresses probed per name (reveals mixed fleets)
	Resolver     safety.Resolver // nil = system resolver
	Sem          chan struct{}   // shared concurrency limit across hosts; nil = 8 per scan
}

// Defaults for Options fields left at zero.
const (
	DefaultSamples      = 3
	DefaultMaxAddresses = 8
)

func (o Options) withDefaults() Options {
	if o.Timeout <= 0 {
		o.Timeout = probe.DefaultTimeout
	}
	if o.Samples <= 0 {
		o.Samples = DefaultSamples
	}
	if o.MaxAddresses <= 0 {
		o.MaxAddresses = DefaultMaxAddresses
	}
	if o.Sem == nil {
		o.Sem = make(chan struct{}, 8)
	}
	return o
}

// probeOne runs the right prober for s against one address (dial), presenting
// name for SNI, and detecting the protocol first if asked.
func probeOne(name, dial string, s Service, o Options) probe.ServiceResult {
	if s.Auto {
		proto, greeting, err := probe.Detect(dial, s.Port, o.Timeout)
		if err != nil {
			return probe.ServiceResult{
				Service: s.Name, Kind: "tls", Protocol: "auto", Host: name, Port: s.Port,
				Address: net.JoinHostPort(dial, strconv.Itoa(s.Port)),
				Banner:  greeting, Error: err.Error(), ErrorKind: probe.ErrorKind(err),
			}
		}
		detected, _ := ForPort(proto, s.Port)
		res := probeOne(name, dial, detected, o)
		res.Detected = true
		return res
	}
	var res probe.ServiceResult
	if s.Family == FamilySSH {
		res = probe.ProbeSSH(s.Name, dial, s.Port, o.Timeout)
	} else {
		res = probe.ProbeTLSWith(s.Name, dial, s.Port, name, s.Preamble, o.Timeout, probe.TLSOptions{Samples: o.Samples, HTTP: s.HTTP})
	}
	res.Host = name
	res.Protocol = s.Protocol
	if res.Address == "" {
		res.Address = net.JoinHostPort(dial, strconv.Itoa(s.Port))
	}
	return res
}

// CheckPath probes a reference server known to support ML-KEM, to learn whether
// this scanner's network path carries ML-KEM handshakes. If it doesn't, every
// classical result from this scanner may be a false negative.
func CheckPath(reference string, timeout time.Duration) *report.PathCheck {
	pc := &report.PathCheck{Reference: reference}
	host, port, err := safety.ParseTarget(reference)
	if err != nil {
		pc.Error = err.Error()
		return pc
	}
	if port == 0 {
		port = 443
	}
	pc.Reference = net.JoinHostPort(host, strconv.Itoa(port))
	r := probe.ProbeTLS("reference", host, port, host, nil, timeout)
	if r.Error != "" {
		pc.Error = r.Error
		return pc
	}
	if h, _, err := net.SplitHostPort(r.Address); err == nil {
		if ip, err := netip.ParseAddr(h); err == nil && ip.IsLoopback() {
			pc.Loopback = true
		}
	}
	offered := len(r.Groups) > 0 && r.Groups[0].Supported
	forced := r.Forced != nil && r.Forced.Completed
	pc.Carried = offered || forced
	outcome := "did not complete"
	if forced {
		outcome = "completed"
	}
	pc.Detail = fmt.Sprintf("server chose %s; ML-KEM-only handshake %s", orDash(r.NegotiatedGroup), outcome)
	return pc
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

// Scan probes every service and returns the host report.
func Scan(host string, svcs []Service, o Options, env report.Env) report.HostReport {
	return ScanStream(context.Background(), host, svcs, o, env, nil)
}

// ScanStream probes every service at every address host resolves to, merging
// each service's per-address results into one row and calling emit (serialized)
// as each service completes. Once ctx is cancelled it launches no more probes,
// emits nothing further, and returns a partial report of what had finished.
func ScanStream(ctx context.Context, host string, svcs []Service, o Options, env report.Env, emit func(report.ServiceReport)) report.HostReport {
	o = o.withDefaults()
	addrs, err := safety.ResolveAll(ctx, o.Resolver, host, o.MaxAddresses)
	if err != nil {
		var results []report.ServiceReport
		for _, s := range svcs {
			sr := report.ForService(probe.ServiceResult{Service: s.Name, Kind: "tls", Protocol: s.Protocol, Host: host, Port: s.Port,
				Error: err.Error(), ErrorKind: "dns"}, env)
			results = append(results, sr)
			if emit != nil {
				emit(sr)
			}
		}
		return report.Rollup(host, results, len(svcs), false, env)
	}

	var (
		mu        sync.Mutex
		wg        sync.WaitGroup
		parts     = make([][]report.ServiceReport, len(svcs))
		remaining = make([]int, len(svcs))
		merged    = make([]*report.ServiceReport, len(svcs))
	)
	for i := range svcs {
		parts[i] = make([]report.ServiceReport, len(addrs))
		remaining[i] = len(addrs)
	}

launch:
	for i, s := range svcs {
		for j, a := range addrs {
			select {
			case <-ctx.Done():
				break launch
			case o.Sem <- struct{}{}:
			}
			if ctx.Err() != nil {
				<-o.Sem
				break launch
			}
			wg.Add(1)
			go func(i, j int, s Service, a netip.Addr) {
				defer wg.Done()
				defer func() { <-o.Sem }()
				sr := report.ForService(probeOne(host, a.String(), s, o), env)
				mu.Lock()
				defer mu.Unlock()
				if ctx.Err() != nil {
					return
				}
				parts[i][j] = sr
				remaining[i]--
				if remaining[i] == 0 {
					m := report.MergeAddresses(parts[i])
					merged[i] = &m
					if emit != nil {
						emit(m)
					}
				}
			}(i, j, s, a)
		}
	}

	finished := make(chan struct{})
	go func() { wg.Wait(); close(finished) }()
	select {
	case <-finished:
	case <-ctx.Done():
	}

	mu.Lock()
	var results []report.ServiceReport
	for _, m := range merged {
		if m != nil {
			results = append(results, *m)
		}
	}
	mu.Unlock()
	return report.Rollup(host, results, len(svcs), len(results) < len(svcs), env)
}

// label names an estate entry: the host, plus the port when the entry named one.
func label(t safety.Target) string {
	if t.Port > 0 {
		return net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
	}
	return t.Host
}

// EstateEvent is one step of an estate scan, streamed to callers.
type EstateEvent struct {
	Type    string                `json:"type"`  // host-start | service | host-done
	Index   int                   `json:"index"` // position in the target list
	Host    string                `json:"host"`
	Planned []Service             `json:"services,omitempty"`
	Service *report.ServiceReport `json:"service,omitempty"`
	Report  *report.HostReport    `json:"report,omitempty"`
}

// ScanEstate scans many targets, a few hosts at a time, sharing one concurrency
// limit for all probes. Targets with a port are probed as that port with
// protocol; the rest get scope. emit (serialized) receives progress events.
func ScanEstate(ctx context.Context, targets []safety.Target, scope []Service, protocol string, o Options, env report.Env, emit func(EstateEvent)) report.EstateReport {
	if o.Sem == nil {
		o.Sem = make(chan struct{}, 16)
	}
	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		results = make([]*report.HostReport, len(targets))
		hostSem = make(chan struct{}, 4)
	)
	send := func(ev EstateEvent) {
		if emit == nil {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if ctx.Err() == nil {
			emit(ev)
		}
	}

launch:
	for i, t := range targets {
		svcs := scope
		if t.Port > 0 {
			s, err := ForPort(protocol, t.Port)
			if err != nil {
				s, _ = ForPort("auto", t.Port)
			}
			svcs = []Service{s}
		}
		select {
		case <-ctx.Done():
			break launch
		case hostSem <- struct{}{}:
		}
		wg.Add(1)
		go func(i int, host, label string, svcs []Service) {
			defer wg.Done()
			defer func() { <-hostSem }()
			send(EstateEvent{Type: "host-start", Index: i, Host: host, Planned: svcs})
			hr := ScanStream(ctx, host, svcs, o, env, func(sr report.ServiceReport) {
				send(EstateEvent{Type: "service", Index: i, Host: host, Service: &sr})
			})
			hr.Target = label
			if ctx.Err() != nil {
				return
			}
			mu.Lock()
			results[i] = &hr
			mu.Unlock()
			send(EstateEvent{Type: "host-done", Index: i, Host: host, Report: &hr})
		}(i, t.Host, label(t), svcs)
	}

	finished := make(chan struct{})
	go func() { wg.Wait(); close(finished) }()
	select {
	case <-finished:
	case <-ctx.Done():
	}

	mu.Lock()
	var hosts []report.HostReport
	for _, r := range results {
		if r != nil {
			hosts = append(hosts, *r)
		}
	}
	mu.Unlock()
	return report.Estate(hosts, len(targets), env)
}
