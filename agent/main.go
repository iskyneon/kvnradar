package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

type Config struct {
	Agent       string `json:"agent"`
	Token       string `json:"token"`
	Server      string `json:"server"`
	CAFile      string `json:"ca_file"`
	StateDir    string `json:"state_dir"`
	SyncSeconds int    `json:"sync_seconds"`
}
type Target struct {
	ID             string   `json:"id"`
	Type           string   `json:"type"`
	URL            string   `json:"url"`
	Host           string   `json:"host"`
	Port           int      `json:"port"`
	MinBytes       int64    `json:"min_bytes"`
	IntervalSec    int      `json:"interval_sec"`
	TimeoutSec     int      `json:"timeout_sec"`
	ExpectedSHA256 string   `json:"sha256"`
	Agents         []string `json:"agents"`
}
type Event struct {
	ID            string         `json:"id"`
	Target        string         `json:"target"`
	TS            string         `json:"ts"`
	Status        string         `json:"status"`
	Bytes         int64          `json:"bytes"`
	ExpectedBytes int64          `json:"expected_bytes"`
	DurationMS    int64          `json:"duration_ms"`
	HTTPCode      int            `json:"http_code,omitempty"`
	Error         string         `json:"error,omitempty"`
	Details       map[string]any `json:"details,omitempty"`
}
type SyncIn struct {
	Agent  string  `json:"agent"`
	Events []Event `json:"events"`
}
type SyncOut struct {
	Accepted []string `json:"accepted"`
	Targets  []Target `json:"targets"`
	Version  int      `json:"config_version"`
}
type State struct {
	Targets []Target         `json:"targets"`
	Pending []Event          `json:"pending"`
	LastRun map[string]int64 `json:"last_run"`
}

var sequence uint64

func stamp() string { return time.Now().UTC().Format(time.RFC3339) }
func save(path string, x any) error {
	b, e := json.MarshalIndent(x, "", "  ")
	if e != nil {
		return e
	}
	tmp := path + ".tmp"
	if e = os.WriteFile(tmp, b, 0600); e != nil {
		return e
	}
	return os.Rename(tmp, path)
}
func load(path string, x any) error {
	b, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	return json.Unmarshal(b, x)
}
func clip(s string) string {
	if len(s) > 220 {
		return s[:220]
	}
	return s
}
func newEvent(t Target) Event {
	return Event{ID: fmt.Sprintf("%d-%d", time.Now().UnixNano(), atomic.AddUint64(&sequence, 1)), Target: t.ID, TS: stamp(), ExpectedBytes: t.MinBytes, Details: map[string]any{}}
}

func probe(t Target) Event {
	e := newEvent(t)
	started := time.Now()
	timeout := time.Duration(t.TimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 25 * time.Second
	}
	defer func() { e.DurationMS = time.Since(started).Milliseconds() }() // not used: explicit setting below
	switch strings.ToLower(t.Type) {
	case "tcp":
		host := t.Host
		if host == "" {
			host = "127.0.0.1"
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		d := net.Dialer{}
		c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(t.Port)))
		if err != nil {
			e.Status = "TCP_FAIL"
			e.Error = clip(err.Error())
		} else {
			e.Status = "OK_TCP"
			c.Close()
		}
	case "tls":
		host := t.Host
		if host == "" {
			host = "127.0.0.1"
		}
		port := t.Port
		if port == 0 {
			port = 443
		}
		dialer := net.Dialer{Timeout: timeout}
		conn, err := tls.DialWithDialer(&dialer, "tcp", net.JoinHostPort(host, strconv.Itoa(port)), &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS13, ServerName: host})
		if err != nil {
			e.Status = "TLS_FAIL"
			e.Error = clip(err.Error())
		} else {
			state := conn.ConnectionState()
			e.Status = "OK_TLS"
			e.Details["tls_version"] = state.Version
			e.Details["cipher_suite"] = state.CipherSuite
			if len(state.PeerCertificates) > 0 {
				e.Details["cert_expires_at"] = state.PeerCertificates[0].NotAfter.UTC().Format(time.RFC3339)
				e.Details["cert_days_left"] = int(time.Until(state.PeerCertificates[0].NotAfter).Hours() / 24)
				if time.Until(state.PeerCertificates[0].NotAfter) < 14*24*time.Hour {
					e.Status = "TLS_CERT_EXPIRING"
				}
			}
			conn.Close()
		}
	case "traceroute":
		host := t.Host
		if host == "" {
			e.Status = "INVALID_HOST"
			break
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		output, err := exec.CommandContext(ctx, "traceroute", "-n", "-m", "12", "-w", "1", "-q", "1", host).CombinedOutput()
		e.Details["trace"] = clip(string(output))
		if err != nil {
			e.Status = "TRACE_FAIL"
			e.Error = clip(err.Error())
		} else {
			e.Status = "OK_TRACE"
		}
	case "dns":
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, t.Host)
		if err != nil {
			e.Status = "DNS_FAIL"
			e.Error = clip(err.Error())
		} else if len(ips) == 0 {
			e.Status = "DNS_EMPTY"
		} else {
			e.Status = "OK_DNS"
			e.Details["addresses"] = len(ips)
		}
	case "icmp":
		// Two ping packets only; runs sequentially. Needs iputils-ping on Linux.
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		output, err := exec.CommandContext(ctx, "ping", "-n", "-c", "2", "-W", "2", t.Host).CombinedOutput()
		if err != nil {
			e.Status = "ICMP_FAIL"
			e.Error = clip(string(output))
		} else {
			e.Status = "OK_ICMP"
		}
	case "http", "https", "", "http_content", "http_status", "ssl_vpn":
		statusOnly := t.Type == "http_status" || t.Type == "ssl_vpn"
		if !statusOnly && t.MinBytes <= 0 {
			t.MinBytes = 65536
			e.ExpectedBytes = t.MinBytes
		}
		if statusOnly {
			e.ExpectedBytes = 0
		}
		if t.URL == "" && (t.Type == "ssl_vpn" || t.Type == "http_status" || t.Type == "http_content") {
			t.URL = "https://" + t.Host + "/"
		}
		u, err := url.Parse(t.URL)
		if err != nil || u.Host == "" {
			e.Status = "INVALID_URL"
			e.Error = "invalid URL"
			break
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			e.Status = "INVALID_URL"
			e.Error = "only http/https allowed"
			break
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		tr := &http.Transport{DisableKeepAlives: true, DisableCompression: true, ForceAttemptHTTP2: false, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS13}, TLSHandshakeTimeout: 8 * time.Second, ResponseHeaderTimeout: 12 * time.Second, MaxIdleConns: 0}
		client := &http.Client{Timeout: timeout, Transport: tr, CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
		req, err := http.NewRequestWithContext(ctx, "GET", t.URL, nil)
		if err != nil {
			e.Status = "INVALID_URL"
			e.Error = clip(err.Error())
			break
		}
		var dnsBegin, connBegin, tlsBegin time.Time
		trace := &httptrace.ClientTrace{
			DNSStart: func(httptrace.DNSStartInfo) { dnsBegin = time.Now() },
			DNSDone: func(httptrace.DNSDoneInfo) {
				if !dnsBegin.IsZero() {
					e.Details["dns_ms"] = time.Since(dnsBegin).Milliseconds()
				}
			},
			ConnectStart: func(_, _ string) { connBegin = time.Now() },
			ConnectDone: func(_, _ string, err error) {
				if err == nil && !connBegin.IsZero() {
					e.Details["tcp_connect_ms"] = time.Since(connBegin).Milliseconds()
				}
			},
			TLSHandshakeStart: func() { tlsBegin = time.Now() },
			TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
				if err == nil && !tlsBegin.IsZero() {
					e.Details["tls_handshake_ms"] = time.Since(tlsBegin).Milliseconds()
				}
			},
			GotFirstResponseByte: func() { e.Details["ttfb_ms"] = time.Since(started).Milliseconds() },
		}
		req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
		req.Header.Set("Accept-Encoding", "identity")
		req.Header.Set("User-Agent", "KVNRadar-Agent/0.1")
		resp, err := client.Do(req)
		if err != nil {
			e.Status = "HTTP_CONNECT_FAIL"
			e.Error = clip(err.Error())
			tr.CloseIdleConnections()
			break
		}
		e.HTTPCode = resp.StatusCode
		e.Details["content_length"] = resp.ContentLength
		e.Details["proto"] = resp.Proto
		e.Details["encoding"] = resp.Header.Get("Content-Encoding")
		if resp.TLS != nil {
			e.Details["tls_version"] = resp.TLS.Version
		}
		if statusOnly && t.Type == "ssl_vpn" && ((resp.StatusCode >= 200 && resp.StatusCode < 400) || resp.StatusCode == 401 || resp.StatusCode == 403) {
			e.Status = "OK_VPN_PORTAL"
			resp.Body.Close()
			tr.CloseIdleConnections()
			break
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 400 {
			e.Status = "HTTP_STATUS"
			e.Error = resp.Status
			resp.Body.Close()
			tr.CloseIdleConnections()
			break
		}
		if statusOnly {
			e.Status = "OK_HTTP"
			resp.Body.Close()
			tr.CloseIdleConnections()
			break
		}
		// Stream body: no buffering entire content; record threshold crossing within ONE request.
		h := sha256.New()
		buf := make([]byte, 4096)
		var total int64
		milestones := map[string]int64{}
		thresholds := []int64{4096, 8192, 16384, 20480, 32768, 65536, 131072}
		var readErr error
		for total < t.MinBytes {
			limit := len(buf)
			if t.MinBytes-total < int64(limit) {
				limit = int(t.MinBytes - total)
			}
			n, err := resp.Body.Read(buf[:limit])
			if n > 0 {
				h.Write(buf[:n])
				total += int64(n)
				for _, v := range thresholds {
					key := strconv.FormatInt(v, 10)
					if total >= v && milestones[key] == 0 {
						milestones[key] = time.Since(started).Milliseconds()
					}
				}
			}
			if err != nil {
				readErr = err
				break
			}
			if n == 0 {
				readErr = errors.New("empty read")
				break
			}
		}
		resp.Body.Close()
		tr.CloseIdleConnections()
		e.Bytes = total
		e.Details["milestones_ms"] = milestones
		if total >= t.MinBytes {
			e.Status = "OK_FULL"
			if t.ExpectedSHA256 != "" && total == t.MinBytes && !strings.EqualFold(hex.EncodeToString(h.Sum(nil)), t.ExpectedSHA256) {
				e.Status = "CONTENT_MISMATCH"
				e.Error = "sha256 mismatch"
			}
		} else if errors.Is(readErr, io.EOF) && resp.ContentLength >= 0 && resp.ContentLength == total {
			e.Status = "SHORT_RESPONSE"
		} else if errors.Is(readErr, io.EOF) && resp.ContentLength < 0 {
			e.Status = "SHORT_RESPONSE"
		} else if readErr != nil {
			if errors.Is(readErr, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) || strings.Contains(strings.ToLower(readErr.Error()), "timeout") {
				if total >= 12000 && total <= 24000 {
					e.Status = "STALL_16K"
				} else {
					e.Status = "TRANSFER_TIMEOUT"
				}
			} else {
				e.Status = "PARTIAL_TRANSFER"
			}
			e.Error = clip(readErr.Error())
		} else {
			e.Status = "PARTIAL_TRANSFER"
		}
	default:
		e.Status = "UNSUPPORTED_PROBE"
		e.Error = t.Type
	}
	e.DurationMS = time.Since(started).Milliseconds()
	return e
}

func syncOnce(c Config, s *State) error {
	pending := s.Pending
	if len(pending) > 100 {
		pending = pending[:100]
	}
	payload, _ := json.Marshal(SyncIn{Agent: c.Agent, Events: pending})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST", c.Server+"/api/sync", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Connection", "close")
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
	if c.CAFile != "" {
		pem, err := os.ReadFile(c.CAFile)
		if err != nil {
			return err
		}
		pool, e := x509.SystemCertPool()
		if e != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return errors.New("invalid CA certificate")
		}
		tlsConfig.RootCAs = pool
	}
	tr := &http.Transport{TLSClientConfig: tlsConfig, DisableKeepAlives: true, ForceAttemptHTTP2: false, MaxIdleConns: 0}
	client := &http.Client{Transport: tr, Timeout: 20 * time.Second}
	defer tr.CloseIdleConnections()
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
		return fmt.Errorf("sync HTTP %d: %s", resp.StatusCode, string(b))
	}
	var reply SyncOut
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1024*1024)).Decode(&reply); err != nil {
		return err
	}
	acknowledged := make(map[string]bool)
	for _, id := range reply.Accepted {
		acknowledged[id] = true
	}
	kept := make([]Event, 0, len(s.Pending))
	for _, ev := range s.Pending {
		if !acknowledged[ev.ID] {
			kept = append(kept, ev)
		}
	}
	s.Pending = kept
	s.Targets = reply.Targets
	log.Printf("sync: accepted=%d remaining=%d targets=%d", len(acknowledged), len(kept), len(s.Targets))
	return nil
}
func main() {
	confPath := "agent.json"
	if len(os.Args) > 1 {
		confPath = os.Args[1]
	}
	var c Config
	if err := load(confPath, &c); err != nil {
		log.Fatal(err)
	}
	if c.Agent == "" || c.Token == "" || c.Server == "" {
		log.Fatal("agent, token and server are mandatory")
	}
	if c.SyncSeconds < 60 {
		c.SyncSeconds = 60
	}
	if c.StateDir == "" {
		c.StateDir = "./state"
	}
	u, err := url.Parse(c.Server)
	if err != nil {
		log.Fatal(err)
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "127.0.0.1" || u.Hostname() == "localhost")) {
		log.Fatal("non-local control server requires HTTPS")
	}
	if err = os.MkdirAll(c.StateDir, 0700); err != nil {
		log.Fatal(err)
	}
	stPath := filepath.Join(c.StateDir, "state.json")
	s := State{LastRun: map[string]int64{}, Pending: []Event{}}
	if err := load(stPath, &s); err != nil && !os.IsNotExist(err) {
		log.Fatal(err)
	}
	if s.LastRun == nil {
		s.LastRun = map[string]int64{}
	}
	if s.Pending == nil {
		s.Pending = []Event{}
	}
	for {
		if err := syncOnce(c, &s); err != nil {
			log.Printf("sync error: %v", err)
		}
		if err := save(stPath, &s); err != nil {
			log.Fatal("failed saving sync state: ", err)
		}
		for _, t := range s.Targets {
			if t.ID == "" {
				continue
			}
			if t.IntervalSec < 60 {
				t.IntervalSec = 300
			}
			if time.Now().Unix()-s.LastRun[t.ID] < int64(t.IntervalSec) {
				continue
			}
			event := probe(t)
			log.Printf("probe %s: %s bytes=%d duration=%dms", t.ID, event.Status, event.Bytes, event.DurationMS)
			s.Pending = append(s.Pending, event)
			s.LastRun[t.ID] = time.Now().Unix()
			if err := save(stPath, &s); err != nil {
				log.Fatal("failed saving measurement: ", err)
			}
		}
		// ONE short control session per cycle. Measurements are delivered next cycle.
		time.Sleep(time.Duration(c.SyncSeconds) * time.Second)
	}
}
