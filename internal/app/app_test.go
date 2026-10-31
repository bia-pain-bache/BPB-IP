package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

type testLogger struct {
	mu   sync.Mutex
	logs []string
}

func (l *testLogger) Printf(format string, values ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.logs = append(l.logs, fmt.Sprintf(format, values...))
}

func (l *testLogger) contains(text string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, line := range l.logs {
		if strings.Contains(line, text) {
			return true
		}
	}
	return false
}

func testConfig() Config {
	return Config{
		ScanInterval:   "30m",
		ProbeURL:       "https://probe.example.test/__down",
		ExpectedBytes:  4,
		TimeoutMS:      1000,
		FetchTimeoutMS: 1000,
		ConcurrentRuns: 2,
		Trials:         2,
	}
}

func TestParseEndpointsDeduplicatesAndSupportsIPv4IPv6(t *testing.T) {
	got, err := ParseEndpoints(
		"# comment\r\n192.0.2.1\r\n192.0.2.1:443\n192.0.2.2 8443\n[2001:db8::1]:443\n2001:db8::2",
	)
	if err != nil {
		t.Fatal(err)
	}
	want := []Endpoint{
		{IP: netip.MustParseAddr("192.0.2.1"), Port: 443},
		{IP: netip.MustParseAddr("192.0.2.2"), Port: 8443},
		{IP: netip.MustParseAddr("2001:db8::1"), Port: 443},
		{IP: netip.MustParseAddr("2001:db8::2"), Port: 443},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ParseEndpoints() = %#v, want %#v", got, want)
	}
}

func TestParseEndpointsRejectsInvalidInput(t *testing.T) {
	if _, err := ParseEndpoints("example.com:443"); err == nil {
		t.Fatal("expected invalid hostname to be rejected")
	}
	if _, err := ParseEndpoints("192.0.2.1:65536"); err == nil {
		t.Fatal("expected invalid port to be rejected")
	}
}

func TestLoadRepositoryConfig(t *testing.T) {
	config, err := LoadConfig(filepath.Join("..", "..", "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if config.Cloudflare.APIToken != "" {
		t.Fatal("repository config should not contain a real API token")
	}
	if len(config.SourceURLs) == 0 {
		t.Fatal("expected repository config to contain a URL source")
	}
	if interval, err := config.ScanIntervalDuration(); err != nil || interval != 30*time.Minute {
		t.Fatalf("scan interval = %s, error = %v; want 30m", interval, err)
	}
}

func TestLoadConfigDefaultsMissingScanInterval(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(configPath, []byte(`{
		"probeUrl":"https://probe.example.test/__down",
		"expectedBytes":4,
		"timeoutMs":1000,
		"fetchTimeoutMs":1000,
		"concurrentRuns":2,
		"trials":2
	}`), 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := LoadConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if config.ScanInterval != "30m" {
		t.Fatalf("missing scanInterval default = %q, want 30m", config.ScanInterval)
	}
}

func TestScanIntervalValidation(t *testing.T) {
	for _, interval := range []string{"", "0", "-1m", "invalid"} {
		config := testConfig()
		config.ScanInterval = interval
		if err := config.Validate(); err == nil {
			t.Errorf("Validate() accepted scanInterval %q", interval)
		}
	}
}

func TestConfigureCloudflareWritesCredentialsToConfig(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.json")
	sourceConfig, err := os.ReadFile(filepath.Join("..", "..", "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, sourceConfig, 0o600); err != nil {
		t.Fatal(err)
	}
	input := "test-zone\nproxy.example.com\ntest-api-token\n"
	if err := ConfigureCloudflare(configPath, strings.NewReader(input)); err != nil {
		t.Fatal(err)
	}
	config, err := LoadConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if config.Cloudflare.ZoneID != "test-zone" ||
		config.Cloudflare.RecordName != "proxy.example.com" ||
		config.Cloudflare.APIToken != "test-api-token" {
		t.Fatalf("Cloudflare config was not persisted: %#v", config.Cloudflare)
	}
	info, err := os.Stat(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("config permissions = %o, want 600", info.Mode().Perm())
	}
}

func TestCollectEndpointsAggregatesBestEffortSourcesAndFilters443(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/list":
			_, _ = io.WriteString(w, "192.0.2.1\n192.0.2.3:8443\n")
		case "/empty":
			w.WriteHeader(http.StatusOK)
		case "/non443":
			_, _ = io.WriteString(w, "192.0.2.9:8443\n")
		case "/unavailable":
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	config := testConfig()
	config.SourceURLs = []string{
		server.URL + "/list",
		server.URL + "/empty",
		server.URL + "/non443",
		server.URL + "/unavailable",
		"",
		"http://insecure.example/list",
	}
	config.SourceDomains = []string{"healthy.example", "missing.example", "empty.example", " "}
	logger := &testLogger{}
	endpoints := collectEndpoints(
		context.Background(),
		"192.0.2.2\n192.0.2.1:8443",
		config,
		logger,
		func(_ context.Context, domain string) ([]net.IPAddr, error) {
			switch domain {
			case "healthy.example":
				return []net.IPAddr{
					{IP: net.ParseIP("192.0.2.1")},
					{IP: net.ParseIP("2001:db8::1")},
				}, nil
			case "missing.example":
				return nil, errors.New("no such host")
			default:
				return nil, nil
			}
		},
		server.Client(),
	)
	want := []Endpoint{
		{IP: netip.MustParseAddr("192.0.2.2"), Port: 443},
		{IP: netip.MustParseAddr("192.0.2.1"), Port: 443},
		{IP: netip.MustParseAddr("2001:db8::1"), Port: 443},
	}
	if !reflect.DeepEqual(endpoints, want) {
		t.Fatalf("CollectEndpoints() = %#v, want %#v", endpoints, want)
	}
	if !logger.contains("/empty: no port 443 endpoints found") {
		t.Error("expected empty URL source to be logged")
	}
	if !logger.contains("/non443: no port 443 endpoints found") {
		t.Error("expected source without port 443 endpoints to be logged")
	}
	if !logger.contains("/unavailable: failed") {
		t.Error("expected failed URL source to be logged")
	}
	if !logger.contains(`sourceUrls[4] (empty): failed: source URL must be a valid HTTPS URL`) {
		t.Error("expected blank and non-HTTPS URL sources to be logged")
	}
	if !logger.contains("missing.example: DNS resolution failed") {
		t.Error("expected DNS failure to be logged")
	}
	if !logger.contains("empty.example: no port 443 endpoints found") {
		t.Error("expected empty domain to be logged")
	}
	if !logger.contains("sourceDomains: empty domain entry") {
		t.Error("expected blank domain to be logged")
	}
}

func TestCheckEndpointsStopsRetriesAndPreservesInputOrder(t *testing.T) {
	config := testConfig()
	endpoints := []Endpoint{
		{IP: netip.MustParseAddr("192.0.2.1"), Port: 443},
		{IP: netip.MustParseAddr("192.0.2.2"), Port: 443},
		{IP: netip.MustParseAddr("192.0.2.3"), Port: 443},
	}
	var mu sync.Mutex
	attempts := make(map[Endpoint]int)
	logger := &testLogger{}
	working := CheckEndpoints(
		context.Background(),
		endpoints,
		config,
		func(_ context.Context, endpoint Endpoint, _ Config) error {
			mu.Lock()
			defer mu.Unlock()
			attempts[endpoint]++
			if endpoint == endpoints[1] {
				return errors.New("probe failed")
			}
			return nil
		},
		logger,
	)
	if !reflect.DeepEqual(working, []Endpoint{endpoints[0], endpoints[2]}) {
		t.Fatalf("working endpoints = %#v", working)
	}
	if attempts[endpoints[1]] != 1 {
		t.Fatalf("failing endpoint was tried %d times, want one", attempts[endpoints[1]])
	}
	if attempts[endpoints[0]] != config.Trials {
		t.Fatalf("healthy endpoint trials = %d, want %d", attempts[endpoints[0]], config.Trials)
	}
}

func TestReconcileDNSBatchesChangesAndPreservesOtherRecordTypes(t *testing.T) {
	var mu sync.Mutex
	var calls []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("unexpected authorization header %q", r.Header.Get("Authorization"))
		}
		mu.Lock()
		calls = append(calls, r.Method+" "+r.URL.Path)
		mu.Unlock()

		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/zones/zone-id/dns_records":
			if r.URL.Query().Get("name") != "proxy.example.com" {
				t.Errorf("unexpected record name query: %q", r.URL.RawQuery)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"success":true,"result_info":{"total_pages":1},"result":[
				{"id":"keep","type":"A","name":"proxy.example.com","content":"192.0.2.1","ttl":1,"proxied":true},
				{"id":"old-a","type":"A","name":"proxy.example.com","content":"192.0.2.2","ttl":1,"proxied":false},
				{"id":"old-aaaa","type":"AAAA","name":"proxy.example.com","content":"2001:db8::2","ttl":1,"proxied":false},
				{"id":"extra-a","type":"A","name":"proxy.example.com","content":"192.0.2.4","ttl":1,"proxied":false},
				{"id":"cname","type":"CNAME","name":"proxy.example.com","content":"elsewhere.example.com","ttl":1,"proxied":false}
			]}`)
		case r.Method == http.MethodPost && r.URL.Path == "/zones/zone-id/dns_records/batch":
			var body struct {
				Deletes []dnsRecordDelete `json:"deletes"`
				Posts   []json.RawMessage `json:"posts"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			wantDeleteIDs := []string{"extra-a", "keep", "old-a", "old-aaaa"}
			if len(body.Deletes) != len(wantDeleteIDs) {
				t.Errorf("batch deletes = %#v", body.Deletes)
			} else {
				for i, id := range wantDeleteIDs {
					if body.Deletes[i].ID != id {
						t.Errorf("batch delete %d = %#v, want ID %q", i, body.Deletes[i], id)
					}
				}
			}
			if len(body.Posts) != 4 {
				t.Fatalf("batch posts = %#v, want all four desired records", body.Posts)
			}
			posts := map[string]dnsRecordPayload{}
			for _, rawPost := range body.Posts {
				var post dnsRecordPayload
				if err := json.Unmarshal(rawPost, &post); err != nil {
					t.Error(err)
				}
				var fields map[string]json.RawMessage
				if err := json.Unmarshal(rawPost, &fields); err != nil {
					t.Error(err)
				}
				if _, hasID := fields["id"]; hasID {
					t.Error("new record payload must not include a read-only ID")
				}
				if post.Proxied || post.TTL != 1 || post.Name != "proxy.example.com" {
					t.Errorf("new record is not DNS-only with automatic TTL: %#v", post)
				}
				posts[post.Type+":"+post.Content] = post
			}
			for _, desired := range []string{
				"A:192.0.2.1", "A:192.0.2.3",
				"AAAA:2001:db8::1", "AAAA:2001:db8::3",
			} {
				if _, ok := posts[desired]; !ok {
					t.Errorf("batch missing desired record %q: %#v", desired, posts)
				}
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"success":true,"result":{"deletes":[],"patches":[],"posts":[]}}`)
		default:
			http.Error(w, "unexpected request", http.StatusNotFound)
		}
	}))
	defer server.Close()

	endpoints := []Endpoint{
		{IP: netip.MustParseAddr("192.0.2.1"), Port: 443},
		{IP: netip.MustParseAddr("192.0.2.3"), Port: 443},
		{IP: netip.MustParseAddr("2001:db8::1"), Port: 443},
		{IP: netip.MustParseAddr("2001:db8::3"), Port: 443},
		{IP: netip.MustParseAddr("192.0.2.4"), Port: 8443},
	}
	client := CloudflareClient{
		ZoneID:  "zone-id",
		Token:   "test-token",
		BaseURL: server.URL,
		Client:  server.Client(),
	}
	if err := client.ReconcileDNS(context.Background(), "proxy.example.com", endpoints); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(calls) != 2 || calls[1] != "POST /zones/zone-id/dns_records/batch" {
		t.Fatalf("expected one list and one batch request, got %v", calls)
	}
}

func TestReconcileDNSRetriesTransientCloudflareFailures(t *testing.T) {
	var mu sync.Mutex
	listCalls := 0
	batchCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/zones/zone-id/dns_records":
			mu.Lock()
			listCalls++
			call := listCalls
			mu.Unlock()
			if call == 1 {
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = io.WriteString(w, `{"success":false,"errors":[{"code":1000,"message":"temporarily unavailable"}]}`)
				return
			}
			recordID := "old"
			if call >= 3 {
				recordID = "latest"
			}
			_, _ = fmt.Fprintf(w, `{"success":true,"result_info":{"total_pages":1},"result":[{"id":%q,"type":"A","name":"proxy.example.com","content":"192.0.2.9","ttl":1,"proxied":false}]}`, recordID)
		case r.Method == http.MethodPost && r.URL.Path == "/zones/zone-id/dns_records/batch":
			var body struct {
				Deletes []dnsRecordDelete `json:"deletes"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			mu.Lock()
			batchCalls++
			call := batchCalls
			mu.Unlock()
			if call == 1 {
				if len(body.Deletes) != 1 || body.Deletes[0].ID != "old" {
					t.Errorf("first batch deletes = %#v", body.Deletes)
				}
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = io.WriteString(w, `{"success":false,"errors":[{"code":1000,"message":"temporarily unavailable"}]}`)
				return
			}
			if len(body.Deletes) != 1 || body.Deletes[0].ID != "latest" {
				t.Errorf("retried batch reused stale record IDs: %#v", body.Deletes)
			}
			_, _ = io.WriteString(w, `{"success":true,"result":{"deletes":[],"posts":[]}}`)
		default:
			http.Error(w, "unexpected request", http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := CloudflareClient{
		ZoneID:  "zone-id",
		Token:   "test-token",
		BaseURL: server.URL,
		Client:  server.Client(),
	}
	endpoints := []Endpoint{{IP: netip.MustParseAddr("192.0.2.1"), Port: 443}}
	if err := client.ReconcileDNS(context.Background(), "proxy.example.com", endpoints); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if listCalls != 3 || batchCalls != 2 {
		t.Fatalf("Cloudflare calls: %d list and %d batch; want 3 and 2", listCalls, batchCalls)
	}
}

func TestReconcileDNSRefusesEmptyHealthySetWithoutAPIRequests(t *testing.T) {
	client := CloudflareClient{ZoneID: "zone", Token: "token"}
	err := client.ReconcileDNS(context.Background(), "proxy.example.com", nil)
	if err == nil || !strings.Contains(err.Error(), "empty endpoint set") {
		t.Fatalf("expected empty endpoint set to be rejected, got %v", err)
	}
}

func TestRunSkipsAllEmptyInputsAndPreservesPreviousResults(t *testing.T) {
	directory := t.TempDir()
	configPath := filepath.Join(directory, "config.json")
	listPath := filepath.Join(directory, "list.txt")
	outputPath := filepath.Join(directory, "results", "ips.json")
	config := `{
		"probeUrl":"https://probe.example.test/__down",
		"expectedBytes":4,
		"timeoutMs":1000,
		"fetchTimeoutMs":1000,
		"concurrentRuns":1,
		"trials":1,
		"sourceUrls":[],
		"sourceDomains":[],
		"cloudflare":{"zoneId":"","recordName":"","apiToken":""}
	}`
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(listPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outputPath, []byte("last-known-results"), 0o600); err != nil {
		t.Fatal(err)
	}

	logger := &testLogger{}
	err := Run(Options{
		ConfigPath: configPath,
		ListPath:   listPath,
		OutputPath: outputPath,
		Logger:     logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "last-known-results" {
		t.Fatalf("empty run changed existing results to %q", got)
	}
	if !logger.contains("skipping scan") {
		t.Fatal("expected the empty run to be logged as skipped")
	}
}

func TestWriteResults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "results", "ips.json")
	endpoints := []Endpoint{
		{IP: netip.MustParseAddr("192.0.2.1"), Port: 443},
		{IP: netip.MustParseAddr("2001:db8::1"), Port: 443},
		{IP: netip.MustParseAddr("192.0.2.2"), Port: 8443},
	}
	if err := writeResults(path, endpoints); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := "[\n  \"192.0.2.1:443\",\n  \"[2001:db8::1]:443\"\n]\n"
	if string(got) != want {
		t.Fatalf("result file = %q, want %q", got, want)
	}
}
