package app

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
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
	if len(config.SourceURLs) != 0 {
		t.Fatal("repository config should not contain default URL sources")
	}
	if len(config.SourceDomains) != 0 {
		t.Fatal("repository config should not contain default domain sources")
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

func TestCloudflareMaxRecordsValidation(t *testing.T) {
	config := testConfig()
	config.Cloudflare.MaxRecords = -1
	if err := config.Validate(); err == nil ||
		!strings.Contains(err.Error(), `config "cloudflare.maxRecords"`) {
		t.Fatalf("Validate() error = %v, want invalid maxRecords error", err)
	}

	config.Cloudflare.MaxRecords = 0
	if err := config.Validate(); err != nil {
		t.Fatalf("Validate() rejected maxRecords=0: %v", err)
	}
}

func TestValidateSourcesRequiresAtLeastOneConfiguredSource(t *testing.T) {
	config := testConfig()
	config.SourceURLs = []string{" ", ""}
	config.SourceDomains = []string{" "}
	if err := ValidateSources(config, filepath.Join(t.TempDir(), "list.txt")); err == nil ||
		!strings.Contains(err.Error(), "no sources configured") {
		t.Fatalf("ValidateSources() error = %v, want no-sources error", err)
	}
}

func TestValidateSourcesAcceptsConfiguredURLOrDomain(t *testing.T) {
	for name, configure := range map[string]func(*Config){
		"url":    func(config *Config) { config.SourceURLs = []string{"https://source.example.test/ips.txt"} },
		"domain": func(config *Config) { config.SourceDomains = []string{"proxy.example.test"} },
	} {
		t.Run(name, func(t *testing.T) {
			config := testConfig()
			configure(&config)
			if err := ValidateSources(config, filepath.Join(t.TempDir(), "list.txt")); err != nil {
				t.Fatalf("ValidateSources() error = %v", err)
			}
		})
	}
}

func TestValidateSourcesAcceptsListWithPort443Endpoint(t *testing.T) {
	listPath := filepath.Join(t.TempDir(), "list.txt")
	if err := os.WriteFile(listPath, []byte("# proxy endpoints\n192.0.2.1:443\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateSources(testConfig(), listPath); err != nil {
		t.Fatalf("ValidateSources() error = %v", err)
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

func TestCheckEndpointsStopsRetriesAndReturnsHealthyEndpoints(t *testing.T) {
	config := testConfig()
	endpoints := []Endpoint{
		{IP: netip.MustParseAddr("192.0.2.1"), Port: 443},
		{IP: netip.MustParseAddr("192.0.2.2"), Port: 443},
		{IP: netip.MustParseAddr("192.0.2.3"), Port: 443},
	}
	var mu sync.Mutex
	attempts := make(map[Endpoint]int)
	logger := &testLogger{}
	results := CheckEndpoints(
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
	if len(results) != 3 ||
		results[0].Status != probeStatusPassed ||
		results[1].Status != probeStatusPassed ||
		results[2].Status != probeStatusFailed ||
		results[2].Error != "probe failed" {
		t.Fatalf("probe results = %#v, want two passed followed by one failed result", results)
	}
	if attempts[endpoints[1]] != 1 {
		t.Fatalf("failing endpoint was tried %d times, want one", attempts[endpoints[1]])
	}
	if attempts[endpoints[0]] != config.Trials {
		t.Fatalf("healthy endpoint trials = %d, want %d", attempts[endpoints[0]], config.Trials)
	}
}

func TestCheckEndpointsUsesConciseLogsAndProbeErrors(t *testing.T) {
	config := testConfig()
	config.Trials = 2
	passed := Endpoint{IP: netip.MustParseAddr("192.0.2.1"), Port: 443}
	failed := Endpoint{IP: netip.MustParseAddr("192.0.2.2"), Port: 443}
	logger := &testLogger{}
	const reason = "context deadline exceeded (Client.Timeout exceeded while awaiting headers)"
	results := CheckEndpoints(
		context.Background(),
		[]Endpoint{passed, failed},
		config,
		func(_ context.Context, endpoint Endpoint, _ Config) error {
			if endpoint == failed {
				return &url.Error{
					Op:  "Get",
					URL: "https://speed.cloudflare.com/__down?bytes=10000",
					Err: errors.New(reason),
				}
			}
			time.Sleep(time.Millisecond)
			return nil
		},
		logger,
	)

	if !logger.contains("[1/2] passed - 192.0.2.1") ||
		!logger.contains("[2/2] passed - 192.0.2.1") {
		t.Errorf("passed trials were not logged in the concise format: %#v", logger.logs)
	}
	if !logger.contains("[1/2] failed - 192.0.2.2: " + reason) {
		t.Errorf("failure log did not contain only the final reason: %#v", logger.logs)
	}
	for _, line := range logger.logs {
		if strings.Contains(line, "https://") || strings.Contains(line, ":443") {
			t.Errorf("log contains redundant URL or port: %q", line)
		}
	}
	for _, result := range results {
		if result.Endpoint == failed && result.Error != reason {
			t.Errorf("CSV error = %q, want %q", result.Error, reason)
		}
		if result.Endpoint == passed && result.Speed <= 0 {
			t.Errorf("passed endpoint aggregate speed = %f, want positive", result.Speed)
		}
	}
}

func TestOrderProbeResultsBySpeedAndStatus(t *testing.T) {
	endpoints := []Endpoint{
		{IP: netip.MustParseAddr("192.0.2.1"), Port: 443},
		{IP: netip.MustParseAddr("192.0.2.2"), Port: 443},
		{IP: netip.MustParseAddr("192.0.2.3"), Port: 443},
	}
	results := []endpointProbeResult{
		{Endpoint: endpoints[0], Status: probeStatusPassed, Speed: 5},
		{Endpoint: endpoints[1], Status: probeStatusPassed, Speed: 10},
		{Endpoint: endpoints[2], Status: probeStatusFailed, Error: "probe failed"},
	}
	got := orderProbeResults(results)
	want := []endpointProbeResult{results[1], results[0], results[2]}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("orderProbeResults() = %#v, want %#v", got, want)
	}
}

func TestLimitCloudflareEndpointsKeepsFastestWithinQuota(t *testing.T) {
	endpoints := make([]Endpoint, 300)
	for index := range endpoints {
		endpoints[index] = Endpoint{
			IP:   netip.AddrFrom4([4]byte{192, 0, byte(index / 256), byte(index%256 + 1)}),
			Port: 443,
		}
	}
	selected := limitCloudflareEndpoints(endpoints, availableCloudflareRecordSlots(250, 25))
	if len(selected) != 225 {
		t.Fatalf("selected %d endpoints, want 225", len(selected))
	}
	if selected[224] != endpoints[224] {
		t.Fatal("selected endpoints do not preserve fastest-first order")
	}
}

func TestAvailableCloudflareRecordSlots(t *testing.T) {
	tests := []struct {
		recordQuota  int
		otherRecords int
		want         int
	}{
		{recordQuota: 200, otherRecords: 2, want: 198},
		{recordQuota: 500, otherRecords: 2, want: 498},
		{recordQuota: 200, otherRecords: 199, want: 1},
		{recordQuota: 200, otherRecords: 200, want: 0},
		{recordQuota: 200, otherRecords: 205, want: 0},
	}
	for _, test := range tests {
		if got := availableCloudflareRecordSlots(test.recordQuota, test.otherRecords); got != test.want {
			t.Errorf("availableCloudflareRecordSlots(%d, %d) = %d, want %d",
				test.recordQuota, test.otherRecords, got, test.want)
		}
	}
}

func TestCloudflareRecordLimit(t *testing.T) {
	tests := []struct {
		name                 string
		configuredMaxRecords int
		availableSlots       int
		want                 int
	}{
		{name: "no configured cap", configuredMaxRecords: 0, availableSlots: 300, want: 300},
		{name: "configured cap below quota", configuredMaxRecords: 50, availableSlots: 300, want: 50},
		{name: "configured cap above quota", configuredMaxRecords: 300, availableSlots: 198, want: 198},
		{name: "configured cap equals quota", configuredMaxRecords: 100, availableSlots: 100, want: 100},
		{name: "no available slots", configuredMaxRecords: 50, availableSlots: 0, want: 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := cloudflareRecordLimit(test.configuredMaxRecords, test.availableSlots); got != test.want {
				t.Errorf("cloudflareRecordLimit(%d, %d) = %d, want %d",
					test.configuredMaxRecords, test.availableSlots, got, test.want)
			}
		})
	}
}

func TestLimitCloudflareEndpointsUsesAvailableSlots(t *testing.T) {
	endpoints := make([]Endpoint, 200)
	for index := range endpoints {
		endpoints[index] = Endpoint{
			IP:   netip.AddrFrom4([4]byte{192, 0, byte(index / 256), byte(index%256 + 1)}),
			Port: 443,
		}
	}
	selected := limitCloudflareEndpoints(endpoints, availableCloudflareRecordSlots(200, 2))
	if len(selected) != 198 {
		t.Fatalf("selected %d endpoints, want 198", len(selected))
	}
	if selected[197] != endpoints[197] {
		t.Fatal("selected endpoints do not preserve fastest-first order")
	}
}

func containsEndpoint(endpoints []Endpoint, target Endpoint) bool {
	for _, endpoint := range endpoints {
		if endpoint == target {
			return true
		}
	}
	return false
}

func TestCountUnmanagedRecords(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/zones/zone-id/dns_records" {
			http.Error(w, "unexpected request", http.StatusNotFound)
			return
		}
		if r.URL.Query().Get("name") != "" {
			t.Errorf("record count request unexpectedly filtered by name: %s", r.URL.RawQuery)
		}
		page := r.URL.Query().Get("page")
		w.Header().Set("Content-Type", "application/json")
		switch page {
		case "1":
			_, _ = io.WriteString(w, `{"success":true,"result_info":{"total_pages":2},"result":[
				{"id":"a","type":"A","name":"text.example.com","content":"192.0.2.1"},
				{"id":"b","type":"MX","name":"example.com","content":"mail.example.com"},
				{"id":"c","type":"TXT","name":"x.example.com","content":"v=spf1"},
				{"id":"f","type":"TXT","name":"text.example.com","content":"v=other"}
			]}`)
		case "2":
			_, _ = io.WriteString(w, `{"success":true,"result_info":{"total_pages":2},"result":[
				{"id":"d","type":"AAAA","name":"TEXT.EXAMPLE.COM.","content":"2001:db8::1"},
				{"id":"e","type":"CNAME","name":"www.example.com","content":"example.com"},
				{"id":"g","type":"CNAME","name":"text.example.com","content":"elsewhere.example.com"}
			]}`)
		default:
			http.Error(w, "unexpected page", http.StatusBadRequest)
		}
	}))
	defer server.Close()

	client := CloudflareClient{
		ZoneID:  "zone-id",
		Token:   "test-token",
		BaseURL: server.URL,
		Client:  server.Client(),
	}
	count, err := client.CountUnmanagedRecords(context.Background(), "text.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if count != 5 {
		t.Fatalf("CountUnmanagedRecords() = %d, want 5", count)
	}
}

func TestGetRecordQuota(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/zones/zone-id/dns_records/usage" {
			http.Error(w, "unexpected request", http.StatusNotFound)
			return
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("unexpected authorization header %q", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"success":true,"result":{"record_quota":500,"record_usage":230}}`)
	}))
	defer server.Close()

	client := CloudflareClient{
		ZoneID: "zone-id", Token: "test-token", BaseURL: server.URL, Client: server.Client(),
	}
	quota, err := client.GetRecordQuota(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if quota != 500 {
		t.Fatalf("GetRecordQuota() = %d, want 500", quota)
	}
}

func TestGetRecordQuotaRejectsAccountLevelQuota(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"success":true,"result":{"record_quota":null,"record_usage":230}}`)
	}))
	defer server.Close()

	client := CloudflareClient{
		ZoneID: "zone-id", Token: "test-token", BaseURL: server.URL, Client: server.Client(),
	}
	if _, err := client.GetRecordQuota(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "record_quota is null") {
		t.Fatalf("GetRecordQuota() error = %v, want unavailable quota error", err)
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
		requestNumber := len(calls)
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
			var body dnsBatchPayload
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			if requestNumber == 2 {
				if len(body.Patches) != 3 || len(body.Deletes) != 1 || len(body.Posts) != 0 {
					t.Errorf("first batch should patch and delete only: %#v", body)
				}
				if len(body.Deletes) == 1 && body.Deletes[0].ID != "old-a" {
					t.Errorf("unexpected record deletion: %#v", body.Deletes)
				}
				patches := map[string]dnsRecordPatch{}
				for _, patch := range body.Patches {
					patches[patch.ID] = patch
					if patch.Proxied || patch.TTL != 1 || patch.Name != "proxy.example.com" {
						t.Errorf("patched record is not DNS-only with automatic TTL: %#v", patch)
					}
				}
				if patches["keep"].Content != "192.0.2.1" ||
					patches["extra-a"].Content != "192.0.2.3" ||
					patches["old-aaaa"].Content != "2001:db8::1" {
					t.Errorf("patches did not preserve matching IPs and update the remaining records: %#v", patches)
				}
			} else {
				if len(body.Patches) != 0 || len(body.Posts) != 1 {
					t.Errorf("second batch should post the remaining record only: %#v", body)
				}
				if len(body.Posts) == 1 &&
					(body.Posts[0].Type != "AAAA" || body.Posts[0].Content != "2001:db8::3") {
					t.Errorf("unexpected remaining post: %#v", body.Posts[0])
				}
				for _, post := range body.Posts {
					if post.Proxied || post.TTL != 1 || post.Name != "proxy.example.com" {
						t.Errorf("new record is not DNS-only with automatic TTL: %#v", post)
					}
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
	deleted, err := client.ReconcileDNSWithDeleted(context.Background(), "proxy.example.com", endpoints)
	if err != nil {
		t.Fatal(err)
	}
	wantDeleted := []Endpoint{
		{IP: netip.MustParseAddr("192.0.2.2"), Port: 443},
		{IP: netip.MustParseAddr("192.0.2.4"), Port: 443},
		{IP: netip.MustParseAddr("2001:db8::2"), Port: 443},
	}
	if !reflect.DeepEqual(deleted, wantDeleted) {
		t.Fatalf("deleted DNS endpoints = %#v, want %#v", deleted, wantDeleted)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(calls) != 3 || calls[0] != "GET /zones/zone-id/dns_records" ||
		calls[1] != "POST /zones/zone-id/dns_records/batch" ||
		calls[2] != "POST /zones/zone-id/dns_records/batch" {
		t.Fatalf("expected list, patch/delete, and post requests, got %v", calls)
	}
}

func TestReconcileDNSPatchesExistingAndPostsRemainder(t *testing.T) {
	records := make(map[string]dnsRecord)
	endpoints := make([]Endpoint, 0, 184)
	for i := 1; i <= 184; i++ {
		ip := netip.MustParseAddr(fmt.Sprintf("192.0.2.%d", i))
		endpoints = append(endpoints, Endpoint{IP: ip, Port: 443})
	}
	for i := 1; i <= 100; i++ {
		id := fmt.Sprintf("record-%03d", i)
		records[id] = dnsRecord{
			ID: id, Type: "A", Name: "proxy.example.com", Content: fmt.Sprintf("198.51.100.%d", i),
		}
	}

	batchCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/zones/zone-id/dns_records":
			current := make([]dnsRecord, 0, len(records))
			for _, record := range records {
				current = append(current, record)
			}
			_ = json.NewEncoder(w).Encode(cloudflareEnvelope[[]dnsRecord]{
				Result: current, Success: true,
			})
		case r.Method == http.MethodPost && r.URL.Path == "/zones/zone-id/dns_records/batch":
			var batch dnsBatchPayload
			if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
				t.Error(err)
				http.Error(w, "invalid batch", http.StatusBadRequest)
				return
			}
			batchCalls++
			if batchCalls == 1 && (len(batch.Patches) != 100 || len(batch.Posts) != 0) {
				t.Errorf("first batch should patch all existing records: %#v", batch)
			}
			if batchCalls == 2 && (len(batch.Patches) != 0 || len(batch.Posts) != 84) {
				t.Errorf("second batch should post only the remaining records: %#v", batch)
			}
			if len(batch.Patches)+len(batch.Posts) > 200 {
				t.Errorf("batch exceeds Cloudflare operation limit: %#v", batch)
			}
			for _, patch := range batch.Patches {
				record := records[patch.ID]
				record.Type = patch.Type
				record.Name = patch.Name
				record.Content = patch.Content
				record.TTL = patch.TTL
				record.Proxied = patch.Proxied
				records[patch.ID] = record
			}
			for _, post := range batch.Posts {
				for _, record := range records {
					if record.Type == post.Type && record.Content == post.Content {
						t.Errorf("posted duplicate %s record while the original still existed", post.Content)
					}
				}
				id := fmt.Sprintf("new-%03d", len(records))
				records[id] = dnsRecord{
					ID: id, Type: post.Type, Name: post.Name, Content: post.Content,
				}
			}
			_, _ = io.WriteString(w, `{"success":true,"result":{"deletes":[],"posts":[]}}`)
		default:
			http.Error(w, "unexpected request", http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := CloudflareClient{
		ZoneID: "zone-id", Token: "test-token", BaseURL: server.URL, Client: server.Client(),
	}
	if err := client.ReconcileDNS(context.Background(), "proxy.example.com", endpoints); err != nil {
		t.Fatal(err)
	}
	if batchCalls != 2 {
		t.Fatalf("batch request count = %d, want patch and post requests", batchCalls)
	}
	if len(records) != len(endpoints) {
		t.Fatalf("final record count = %d, want %d", len(records), len(endpoints))
	}
}

func TestReconcileDNSPostsWhenHostnameHasNoRecords(t *testing.T) {
	batchCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/zones/zone-id/dns_records":
			_, _ = io.WriteString(w, `{"success":true,"result_info":{"total_pages":1},"result":[]}`)
		case r.Method == http.MethodPost && r.URL.Path == "/zones/zone-id/dns_records/batch":
			var batch dnsBatchPayload
			if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
				t.Error(err)
			}
			batchCalls++
			if len(batch.Patches) != 0 || len(batch.Posts) != 1 ||
				batch.Posts[0].Content != "192.0.2.1" {
				t.Errorf("expected a post-only batch for the new hostname: %#v", batch)
			}
			_, _ = io.WriteString(w, `{"success":true,"result":{"posts":[]}}`)
		default:
			http.Error(w, "unexpected request", http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := CloudflareClient{
		ZoneID: "zone-id", Token: "test-token", BaseURL: server.URL, Client: server.Client(),
	}
	endpoints := []Endpoint{{IP: netip.MustParseAddr("192.0.2.1"), Port: 443}}
	if err := client.ReconcileDNS(context.Background(), "proxy.example.com", endpoints); err != nil {
		t.Fatal(err)
	}
	if batchCalls != 1 {
		t.Fatalf("batch request count = %d, want one post batch", batchCalls)
	}
}

func TestReconcileDNSPostsInBatchesOf200(t *testing.T) {
	var batches []int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/zones/zone-id/dns_records":
			_, _ = io.WriteString(w, `{"success":true,"result_info":{"total_pages":1},"result":[]}`)
		case r.Method == http.MethodPost && r.URL.Path == "/zones/zone-id/dns_records/batch":
			var batch dnsBatchPayload
			if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
				t.Error(err)
				http.Error(w, "invalid batch", http.StatusBadRequest)
				return
			}
			size := len(batch.Patches) + len(batch.Deletes) + len(batch.Posts)
			if size == 0 || size > cloudflareMaxBatchOperations {
				t.Errorf("batch has %d operations", size)
			}
			batches = append(batches, size)
			_, _ = io.WriteString(w, `{"success":true,"result":{"posts":[]}}`)
		default:
			http.Error(w, "unexpected request", http.StatusNotFound)
		}
	}))
	defer server.Close()

	endpoints := make([]Endpoint, 300)
	for index := range endpoints {
		endpoints[index] = Endpoint{
			IP:   netip.MustParseAddr(fmt.Sprintf("2001:db8::%x", index+1)),
			Port: 443,
		}
	}
	client := CloudflareClient{
		ZoneID: "zone-id", Token: "test-token", BaseURL: server.URL, Client: server.Client(),
	}
	if err := client.ReconcileDNS(context.Background(), "proxy.example.com", endpoints); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(batches, []int{200, 100}) {
		t.Fatalf("post batch sizes = %v, want [200 100]", batches)
	}
}

func TestReconcileDNSDeletesRecordsBeyondDesiredSet(t *testing.T) {
	records := []dnsRecord{
		{ID: "keep", Type: "A", Name: "proxy.example.com", Content: "192.0.2.1"},
		{ID: "old-a", Type: "A", Name: "proxy.example.com", Content: "192.0.2.2"},
		{ID: "old-aaaa", Type: "AAAA", Name: "proxy.example.com", Content: "2001:db8::2"},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/zones/zone-id/dns_records":
			_ = json.NewEncoder(w).Encode(cloudflareEnvelope[[]dnsRecord]{
				Result: records, Success: true,
			})
		case r.Method == http.MethodPost && r.URL.Path == "/zones/zone-id/dns_records/batch":
			var batch dnsBatchPayload
			if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
				t.Error(err)
			}
			if len(batch.Patches) != 1 || batch.Patches[0].ID != "keep" ||
				len(batch.Deletes) != 2 || len(batch.Posts) != 0 {
				t.Errorf("expected one patch and two deletes, got %#v", batch)
			}
			if len(batch.Deletes) == 2 &&
				(batch.Deletes[0].ID != "old-a" || batch.Deletes[1].ID != "old-aaaa") {
				t.Errorf("unexpected records deleted: %#v", batch.Deletes)
			}
			_, _ = io.WriteString(w, `{"success":true,"result":{"deletes":[],"patches":[]}}`)
		default:
			http.Error(w, "unexpected request", http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := CloudflareClient{
		ZoneID: "zone-id", Token: "test-token", BaseURL: server.URL, Client: server.Client(),
	}
	endpoints := []Endpoint{{IP: netip.MustParseAddr("192.0.2.3"), Port: 443}}
	deleted, err := client.ReconcileDNSWithDeleted(context.Background(), "proxy.example.com", endpoints)
	if err != nil {
		t.Fatal(err)
	}
	wantDeleted := []Endpoint{
		{IP: netip.MustParseAddr("192.0.2.1"), Port: 443},
		{IP: netip.MustParseAddr("192.0.2.2"), Port: 443},
		{IP: netip.MustParseAddr("2001:db8::2"), Port: 443},
	}
	if !reflect.DeepEqual(deleted, wantDeleted) {
		t.Fatalf("deleted DNS endpoints = %#v, want %#v", deleted, wantDeleted)
	}
}

func TestReconcileDNSWithEmptySelectionDeletesManagedRecords(t *testing.T) {
	record := dnsRecord{
		ID: "old", Type: "A", Name: "proxy.example.com", Content: "192.0.2.9",
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/zones/zone-id/dns_records":
			_ = json.NewEncoder(w).Encode(cloudflareEnvelope[[]dnsRecord]{
				Result: []dnsRecord{record}, Success: true,
			})
		case r.Method == http.MethodPost && r.URL.Path == "/zones/zone-id/dns_records/batch":
			var batch dnsBatchPayload
			if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
				t.Error(err)
			}
			if len(batch.Deletes) != 1 || batch.Deletes[0].ID != record.ID ||
				len(batch.Patches) != 0 || len(batch.Posts) != 0 {
				t.Errorf("expected managed record deletion, got %#v", batch)
			}
			_, _ = io.WriteString(w, `{"success":true,"result":{"deletes":[]}}`)
		default:
			http.Error(w, "unexpected request", http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := CloudflareClient{
		ZoneID: "zone-id", Token: "test-token", BaseURL: server.URL, Client: server.Client(),
	}
	deleted, err := client.ReconcileDNSWithDeleted(context.Background(), "proxy.example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	wantDeleted := []Endpoint{{IP: netip.MustParseAddr("192.0.2.9"), Port: 443}}
	if !reflect.DeepEqual(deleted, wantDeleted) {
		t.Fatalf("deleted DNS endpoints = %#v, want %#v", deleted, wantDeleted)
	}
}

func TestBuildDNSChangeBatchesKeepsEachBatchWithinCloudflareLimit(t *testing.T) {
	patches := make([]dnsRecordPatch, 300)
	deletes := make([]dnsRecordDelete, 300)
	for i := range patches {
		patches[i].ID = fmt.Sprintf("patch-%03d", i)
		deletes[i].ID = fmt.Sprintf("delete-%03d", i)
	}

	batches := buildDNSChangeBatches(patches, deletes)
	if len(batches) != 3 {
		t.Fatalf("batch count = %d, want 3", len(batches))
	}
	wantOperations := []int{200, 200, 200}
	patchCount, deleteCount := 0, 0
	for index, batch := range batches {
		operationCount := len(batch.Patches) + len(batch.Deletes)
		if operationCount == 0 || operationCount > cloudflareMaxBatchOperations {
			t.Errorf("batch %d has %d operations", index, operationCount)
		}
		if operationCount != wantOperations[index] {
			t.Errorf("batch %d has %d operations, want %d", index, operationCount, wantOperations[index])
		}
		patchCount += len(batch.Patches)
		deleteCount += len(batch.Deletes)
	}
	if patchCount != len(patches) || deleteCount != len(deletes) {
		t.Fatalf("batches contain %d patches and %d deletes; want %d and %d",
			patchCount, deleteCount, len(patches), len(deletes))
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
				Patches []dnsRecordPatch `json:"patches"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			mu.Lock()
			batchCalls++
			call := batchCalls
			mu.Unlock()
			if call == 1 {
				if len(body.Patches) != 1 || body.Patches[0].ID != "old" {
					t.Errorf("first batch patches = %#v", body.Patches)
				}
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = io.WriteString(w, `{"success":false,"errors":[{"code":1000,"message":"temporarily unavailable"}]}`)
				return
			}
			if len(body.Patches) != 1 || body.Patches[0].ID != "latest" {
				t.Errorf("retried patch batch changed record IDs: %#v", body.Patches)
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

func TestRunRejectsAllEmptyInputsAndPreservesPreviousResults(t *testing.T) {
	directory := t.TempDir()
	configPath := filepath.Join(directory, "config.json")
	listPath := filepath.Join(directory, "list.txt")
	resultsDir := filepath.Join(directory, "results")
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
	if err := os.MkdirAll(resultsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	oldReport := filepath.Join(resultsDir, "previous.csv")
	if err := os.WriteFile(oldReport, []byte("last-known-results"), 0o600); err != nil {
		t.Fatal(err)
	}

	logger := &testLogger{}
	err := Run(Options{
		ConfigPath: configPath,
		ListPath:   listPath,
		ResultsDir: resultsDir,
		Logger:     logger,
	})
	if err == nil || !strings.Contains(err.Error(), "no sources configured") {
		t.Fatalf("Run() error = %v, want no-sources error", err)
	}
	got, err := os.ReadFile(oldReport)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "last-known-results" {
		t.Fatalf("empty run changed existing results to %q", got)
	}
}

func TestWriteScanResults(t *testing.T) {
	resultsDir := t.TempDir()
	results := []endpointProbeResult{
		{
			Endpoint: Endpoint{IP: netip.MustParseAddr("192.0.2.1"), Port: 443},
			Status:   probeStatusPassed,
			Speed:    12.34,
		},
		{
			Endpoint: Endpoint{IP: netip.MustParseAddr("2001:db8::1"), Port: 443},
			Status:   probeStatusFailed,
			Error:    "probe timed out",
		},
	}
	deleted := []Endpoint{
		{IP: netip.MustParseAddr("192.0.2.2"), Port: 443},
	}
	scannedAt := time.Date(2026, 11, 1, 0, 13, 56, 0, time.UTC)
	path, err := writeScanResults(resultsDir, results, deleted, scannedAt)
	if err != nil {
		t.Fatal(err)
	}
	filename := filepath.Base(path)
	if filename != "results-2026-11-01--00-13-56.csv" {
		t.Fatalf("report filename = %q, want results-2026-11-01--00-13-56.csv", filename)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	got, err := csv.NewReader(file).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"IP", "Status", "Speed (KB/s)", "Error"},
		{"192.0.2.1", "passed", "12939.43", ""},
		{"2001:db8::1", "failed", "", "probe timed out"},
		{"192.0.2.2", "deleted", "", ""},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("scan report rows = %#v, want %#v", got, want)
	}
}
