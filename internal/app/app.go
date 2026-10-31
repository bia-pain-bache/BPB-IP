package app

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
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
	OutputPath string
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
	if options.OutputPath == "" {
		options.OutputPath = filepath.Join("results", "ips.json")
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
	endpoints := CollectEndpoints(options.Context, string(localContents), config, options.Logger, nil)
	if len(endpoints) == 0 {
		options.Logger.Printf("no port 443 endpoints found across list.txt, sourceUrls, and sourceDomains; skipping scan")
		return nil
	}

	working := CheckEndpoints(options.Context, endpoints, config, ProbeEndpoint, options.Logger)
	if err := writeResults(options.OutputPath, working); err != nil {
		return err
	}
	options.Logger.Printf("wrote %d working endpoints to %s", len(working), options.OutputPath)
	if len(working) == 0 {
		return fmt.Errorf("no healthy endpoints; preserving existing Cloudflare DNS records")
	}

	recordName := strings.TrimSpace(config.Cloudflare.RecordName)
	if options.DryRun {
		options.Logger.Printf("dry run: would update DNS-only A/AAAA records for %s with %d endpoints", recordName, len(working))
		return nil
	}
	token := strings.TrimSpace(config.Cloudflare.APIToken)
	if token == "" {
		return fmt.Errorf(`Cloudflare API token is empty in config "cloudflare.apiToken"`)
	}
	client := CloudflareClient{
		ZoneID: config.Cloudflare.ZoneID,
		Token:  token,
		Client: &http.Client{Timeout: 30 * time.Second},
	}
	if err := client.ReconcileDNS(options.Context, recordName, working); err != nil {
		return err
	}
	options.Logger.Printf("updated DNS-only A/AAAA records for %s", recordName)
	return nil
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

func writeResults(path string, endpoints []Endpoint) error {
	results := make([]string, 0, len(endpoints))
	for _, endpoint := range endpoints {
		if endpoint.Port == 443 {
			results = append(results, endpoint.String())
		}
	}
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return fmt.Errorf("encode results: %w", err)
	}
	data = append(data, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create results directory: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write results file %s: %w", path, err)
	}
	return nil
}

type domainResolver func(context.Context, string) ([]net.IPAddr, error)
