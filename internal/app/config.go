package app

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"time"
)

type Config struct {
	ScanInterval   string   `json:"scanInterval"`
	ProbeURL       string   `json:"probeUrl"`
	ExpectedBytes  int64    `json:"expectedBytes"`
	TimeoutMS      int      `json:"timeoutMs"`
	FetchTimeoutMS int      `json:"fetchTimeoutMs"`
	ConcurrentRuns int      `json:"concurrentRuns"`
	Trials         int      `json:"trials"`
	SourceURLs     []string `json:"sourceUrls"`
	SourceDomains  []string `json:"sourceDomains"`
	EnableArchive  bool     `json:"enableArchive"`
	IncludeArchive bool     `json:"includeArchive"`
	Cloudflare     struct {
		ZoneID     string `json:"zoneId"`
		RecordName string `json:"recordName"`
		APIToken   string `json:"apiToken"`
		MaxRecords int    `json:"maxRecords"`
	} `json:"cloudflare"`
}

func LoadConfig(path string) (Config, error) {
	config := Config{ScanInterval: "30m", EnableArchive: true}
	data, err := os.ReadFile(path)
	if err != nil {
		return config, fmt.Errorf("read config %s: %w", path, err)
	}
	if err := json.Unmarshal(data, &config); err != nil {
		return config, fmt.Errorf("parse config %s: %w", path, err)
	}
	if err := config.Validate(); err != nil {
		return config, err
	}
	return config, nil
}

func (c *Config) Validate() error {
	if _, err := c.ScanIntervalDuration(); err != nil {
		return err
	}
	if c.ExpectedBytes < 1 {
		return fmt.Errorf(`config "expectedBytes" must be a positive integer`)
	}
	if c.TimeoutMS < 1 || c.FetchTimeoutMS < 1 {
		return fmt.Errorf(`config timeouts must be positive integers`)
	}
	if c.ConcurrentRuns < 1 || c.Trials < 1 {
		return fmt.Errorf(`config "concurrentRuns" and "trials" must be positive integers`)
	}
	if c.Cloudflare.MaxRecords < 0 {
		return fmt.Errorf(`config "cloudflare.maxRecords" must be zero or a positive integer`)
	}
	probeURL, err := url.ParseRequestURI(c.ProbeURL)
	if err != nil || probeURL.Scheme != "https" || probeURL.Hostname() == "" {
		return fmt.Errorf(`config "probeUrl" must be a valid HTTPS URL`)
	}
	if probeURL.Port() != "" && probeURL.Port() != "443" {
		return fmt.Errorf(`config "probeUrl" must use port 443`)
	}
	return nil
}

func (c Config) ScanIntervalDuration() (time.Duration, error) {
	interval, err := time.ParseDuration(c.ScanInterval)
	if err != nil || interval <= 0 {
		return 0, fmt.Errorf(`config "scanInterval" must be a positive duration such as "30m"`)
	}
	return interval, nil
}
