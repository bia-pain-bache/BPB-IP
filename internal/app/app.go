package app

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Logger interface {
	Printf(format string, values ...any)
}

type Options struct {
	Context    context.Context
	ConfigPath string
	ListPath   string
	ResultsDir string
	DryRun     bool
	Logger     Logger
}

func Run(options Options) error {
	if options.ConfigPath == "" {
		options.ConfigPath = "config.json"
	}
	if options.ListPath == "" {
		options.ListPath = "list.txt"
	}
	if options.ResultsDir == "" {
		options.ResultsDir = "results"
	}
	if options.Logger == nil {
		options.Logger = log.New(os.Stdout, "", log.LstdFlags)
	}
	if options.Context == nil {
		options.Context = context.Background()
	}

	config, err := LoadConfig(options.ConfigPath)
	if err != nil {
		return err
	}
	localContents, err := os.ReadFile(options.ListPath)
	if err != nil {
		options.Logger.Printf("list.txt: failed to read %s: %v", options.ListPath, err)
		localContents = nil
	}
	if err := validateSources(config, string(localContents), options.ListPath); err != nil {
		return err
	}
	endpoints := CollectEndpoints(options.Context, string(localContents), config, options.Logger, nil)
	if len(endpoints) == 0 {
		path, err := writeScanResults(options.ResultsDir, nil, nil, time.Now())
		if err != nil {
			return err
		}
		options.Logger.Printf("no port 443 endpoints found across list.txt, sourceUrls, and sourceDomains; wrote empty scan report to %s", path)
		return nil
	}

	results := CheckEndpoints(options.Context, endpoints, config, ProbeEndpoint, options.Logger)
	working := make([]Endpoint, 0, len(results))
	for _, result := range results {
		if result.Status == probeStatusPassed {
			working = append(working, result.Endpoint)
		}
	}
	if len(working) == 0 {
		path, err := writeScanResults(options.ResultsDir, results, nil, time.Now())
		if err != nil {
			return err
		}
		options.Logger.Printf("wrote scan report to %s", path)
		return fmt.Errorf("no healthy endpoints; preserving existing Cloudflare DNS records")
	}

	recordName := strings.TrimSpace(config.Cloudflare.RecordName)
	if options.DryRun {
		options.Logger.Printf("dry run: would update DNS-only A/AAAA records for %s with %d fastest healthy endpoints; record quota not checked", recordName, len(working))
		path, err := writeScanResults(options.ResultsDir, results, nil, time.Now())
		if err != nil {
			return err
		}
		options.Logger.Printf("wrote scan report to %s", path)
		return nil
	}
	token := strings.TrimSpace(config.Cloudflare.APIToken)
	if token == "" {
		if _, err := writeScanResults(options.ResultsDir, results, nil, time.Now()); err != nil {
			return err
		}
		return fmt.Errorf(`Cloudflare API token is empty in config "cloudflare.apiToken"`)
	}
	client := CloudflareClient{
		ZoneID: config.Cloudflare.ZoneID,
		Token:  token,
	}
	recordQuota, err := client.GetRecordQuota(options.Context)
	if err != nil {
		if _, writeErr := writeScanResults(options.ResultsDir, results, nil, time.Now()); writeErr != nil {
			return fmt.Errorf("%w (also failed to write scan report: %v)", err, writeErr)
		}
		return err
	}
	otherRecordCount, err := client.CountUnmanagedRecords(options.Context, recordName)
	if err != nil {
		if _, writeErr := writeScanResults(options.ResultsDir, results, nil, time.Now()); writeErr != nil {
			return fmt.Errorf("%w (also failed to write scan report: %v)", err, writeErr)
		}
		return err
	}
	availableSlots := availableCloudflareRecordSlots(recordQuota, otherRecordCount)
	configuredMaxRecords := config.Cloudflare.MaxRecords
	if configuredMaxRecords > availableSlots {
		options.Logger.Printf(
			"configured cloudflare.maxRecords is %d, but only %d Cloudflare DNS record slots are available; limiting maxRecords to %d",
			configuredMaxRecords,
			availableSlots,
			availableSlots,
		)
	}
	uploadSlots := cloudflareRecordLimit(configuredMaxRecords, availableSlots)
	uploadEndpoints := limitCloudflareEndpoints(working, uploadSlots)
	options.Logger.Printf(
		"Cloudflare zone quota is %d records with %d unmanaged records; using %d of %d available record slots for the fastest IPs",
		recordQuota,
		otherRecordCount,
		len(uploadEndpoints),
		availableSlots,
	)
	if len(uploadEndpoints) == 0 {
		deleted, reconcileErr := client.ReconcileDNSWithDeleted(options.Context, recordName, nil)
		path, writeErr := writeScanResults(options.ResultsDir, results, deleted, time.Now())
		if writeErr != nil {
			if reconcileErr != nil {
				return fmt.Errorf("%w (also failed to write scan report: %v)", reconcileErr, writeErr)
			}
			return writeErr
		}
		if reconcileErr != nil {
			return reconcileErr
		}
		options.Logger.Printf("wrote scan report to %s", path)
		if len(deleted) > 0 {
			return fmt.Errorf("Cloudflare DNS record limit reached: no record slots available outside %s; removed %d managed IP records", recordName, len(deleted))
		}
		return fmt.Errorf("Cloudflare DNS record limit reached: no record slots available outside %s", recordName)
	}
	deleted, reconcileErr := client.ReconcileDNSWithDeleted(options.Context, recordName, uploadEndpoints)
	path, writeErr := writeScanResults(options.ResultsDir, results, deleted, time.Now())
	if writeErr != nil {
		if reconcileErr != nil {
			return fmt.Errorf("%w (also failed to write scan report: %v)", reconcileErr, writeErr)
		}
		return writeErr
	}
	if reconcileErr != nil {
		return reconcileErr
	}
	options.Logger.Printf("updated DNS-only A/AAAA records for %s with %d fastest endpoints", recordName, len(uploadEndpoints))
	options.Logger.Printf("wrote scan report to %s", path)
	return nil
}

func availableCloudflareRecordSlots(recordQuota, otherRecordCount int) int {
	available := recordQuota - otherRecordCount
	if available < 0 {
		return 0
	}
	return available
}

func cloudflareRecordLimit(configuredMaxRecords, availableSlots int) int {
	if configuredMaxRecords > 0 && configuredMaxRecords < availableSlots {
		return configuredMaxRecords
	}
	return availableSlots
}

func limitCloudflareEndpoints(endpoints []Endpoint, limit int) []Endpoint {
	if limit <= 0 {
		return nil
	}
	if limit < len(endpoints) {
		return endpoints[:limit]
	}
	return endpoints
}

func ValidateSources(config Config, listPath string) error {
	if hasRemoteSources(config) {
		return nil
	}
	localContents, err := os.ReadFile(listPath)
	if err != nil {
		if os.IsNotExist(err) {
			localContents = nil
		} else {
			return fmt.Errorf("read source list %s: %w", listPath, err)
		}
	}
	return validateSources(config, string(localContents), listPath)
}

func validateSources(config Config, localContents, listPath string) error {
	if hasRemoteSources(config) {
		return nil
	}
	endpoints, err := ParseEndpoints(localContents)
	if err != nil {
		return fmt.Errorf("no usable sources configured; invalid endpoint data in %s: %w", listPath, err)
	}
	for _, endpoint := range endpoints {
		if endpoint.Port == 443 {
			return nil
		}
	}
	return fmt.Errorf("no sources configured: add a source URL or domain to config, or a port 443 endpoint to %s", listPath)
}

func hasRemoteSources(config Config) bool {
	for _, source := range config.SourceURLs {
		if strings.TrimSpace(source) != "" {
			return true
		}
	}
	for _, domain := range config.SourceDomains {
		if strings.TrimSpace(domain) != "" {
			return true
		}
	}
	return false
}

func ConfigureCloudflare(path string, input io.Reader) error {
	scanner := bufio.NewScanner(input)
	values := make([]string, 3)
	labels := []string{"Cloudflare zone ID", "Dedicated DNS hostname", "Cloudflare API token"}
	for index, label := range labels {
		if !scanner.Scan() {
			return fmt.Errorf("read %s: expected one input line", label)
		}
		values[index] = strings.TrimSpace(scanner.Text())
		if values[index] == "" {
			return fmt.Errorf("%s cannot be empty", label)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read Cloudflare configuration: %w", err)
	}

	config, err := LoadConfig(path)
	if err != nil {
		return err
	}
	config.Cloudflare.ZoneID = values[0]
	config.Cloudflare.RecordName = values[1]
	config.Cloudflare.APIToken = values[2]
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write config %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("restrict config permissions: %w", err)
	}
	return nil
}

func writeScanResults(resultsDir string, results []endpointProbeResult, deleted []Endpoint, scannedAt time.Time) (string, error) {
	if err := os.MkdirAll(resultsDir, 0o755); err != nil {
		return "", fmt.Errorf("create results directory %s: %w", resultsDir, err)
	}
	timestamp := scannedAt.Format("2006-01-02--15-04-05")
	var path string
	var file *os.File
	var err error
	for suffix := 0; ; suffix++ {
		name := "results-" + timestamp
		if suffix > 0 {
			name += "-" + strconv.Itoa(suffix)
		}
		path = filepath.Join(resultsDir, name+".csv")
		file, err = os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if err == nil {
			break
		}
		if !os.IsExist(err) {
			return "", fmt.Errorf("create scan report %s: %w", path, err)
		}
	}

	writer := csv.NewWriter(file)
	if err := writer.Write([]string{"IP", "Status", "Speed (KB/s)", "Error"}); err != nil {
		_ = file.Close()
		return "", fmt.Errorf("write scan report header: %w", err)
	}
	for _, result := range results {
		speed := ""
		if result.Status == probeStatusPassed {
			speed = fmt.Sprintf("%.2f", result.Speed*1024*1024/1000)
		}
		if err := writer.Write([]string{result.Endpoint.IP.String(), result.Status, speed, result.Error}); err != nil {
			_ = file.Close()
			return "", fmt.Errorf("write scan report row: %w", err)
		}
	}
	for _, endpoint := range deleted {
		if !endpoint.IP.IsValid() {
			continue
		}
		if err := writer.Write([]string{endpoint.IP.Unmap().String(), probeStatusDeleted, "", ""}); err != nil {
			_ = file.Close()
			return "", fmt.Errorf("write deleted endpoint to scan report: %w", err)
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		_ = file.Close()
		return "", fmt.Errorf("flush scan report: %w", err)
	}
	if err := file.Close(); err != nil {
		return "", fmt.Errorf("close scan report: %w", err)
	}
	return path, nil
}

type domainResolver func(context.Context, string) ([]net.IPAddr, error)
