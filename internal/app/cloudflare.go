package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

const cloudflareAPIURL = "https://api.cloudflare.com/client/v4"

type CloudflareClient struct {
	ZoneID  string
	Token   string
	BaseURL string
	Client  *http.Client
}

type dnsRecord struct {
	ID       string         `json:"id"`
	Type     string         `json:"type"`
	Name     string         `json:"name"`
	Content  string         `json:"content"`
	TTL      int            `json:"ttl"`
	Proxied  bool           `json:"proxied"`
	Comment  string         `json:"comment,omitempty"`
	Tags     []string       `json:"tags,omitempty"`
	Settings map[string]any `json:"settings,omitempty"`
}

type dnsRecordPayload struct {
	Type     string         `json:"type"`
	Name     string         `json:"name"`
	Content  string         `json:"content"`
	TTL      int            `json:"ttl"`
	Proxied  bool           `json:"proxied"`
	Comment  string         `json:"comment,omitempty"`
	Tags     []string       `json:"tags,omitempty"`
	Settings map[string]any `json:"settings,omitempty"`
}

type cloudflareEnvelope[T any] struct {
	Result  T    `json:"result"`
	Success bool `json:"success"`
	Errors  []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
	ResultInfo struct {
		TotalPages int `json:"total_pages"`
	} `json:"result_info"`
}

func (c CloudflareClient) ReconcileDNS(ctx context.Context, recordName string, endpoints []Endpoint) error {
	if strings.TrimSpace(c.ZoneID) == "" {
		return fmt.Errorf("Cloudflare zoneId is required")
	}
	if strings.TrimSpace(recordName) == "" {
		return fmt.Errorf("Cloudflare recordName is required")
	}
	if strings.TrimSpace(c.Token) == "" {
		return fmt.Errorf("Cloudflare API token is empty")
	}
	if len(endpoints) == 0 {
		return fmt.Errorf("refusing to update DNS with an empty endpoint set")
	}

	desired := make(map[string]map[string]struct{})
	for _, endpoint := range endpoints {
		ip := endpoint.IP.Unmap()
		if endpoint.Port != 443 || !ip.IsValid() {
			continue
		}
		recordType := "A"
		if ip.Is6() {
			recordType = "AAAA"
		}
		if desired[recordType] == nil {
			desired[recordType] = make(map[string]struct{})
		}
		desired[recordType][ip.String()] = struct{}{}
	}
	if len(desired) == 0 {
		return fmt.Errorf("refusing to update DNS: no valid port 443 IP addresses")
	}

	records, err := c.listRecords(ctx, recordName)
	if err != nil {
		return err
	}

	kept := make(map[string]bool)
	creates := make([]dnsRecord, 0)
	for recordType, addresses := range desired {
		for address := range addresses {
			found := false
			for _, record := range records {
				if record.Type == recordType && sameIPContent(record.Content, address) &&
					equalDNSName(record.Name, recordName) && !kept[record.ID] {
					kept[record.ID] = true
					found = true
					if record.Proxied {
						record.Proxied = false
						if record.TTL < 1 {
							record.TTL = 1
						}
						if err := c.updateRecord(ctx, record); err != nil {
							return err
						}
					}
					break
				}
			}
			if !found {
				creates = append(creates, dnsRecord{
					Type: recordType, Name: recordName, Content: address, TTL: 1, Proxied: false,
				})
			}
		}
	}

	// Add every new answer before removing old ones so an API failure cannot
	// leave the managed hostname without any of its previously working answers.
	for _, record := range creates {
		if err := c.createRecord(ctx, record); err != nil {
			return err
		}
	}
	for _, record := range records {
		if (record.Type == "A" || record.Type == "AAAA") &&
			equalDNSName(record.Name, recordName) && !kept[record.ID] {
			if err := c.deleteRecord(ctx, record.ID); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c CloudflareClient) listRecords(ctx context.Context, recordName string) ([]dnsRecord, error) {
	var records []dnsRecord
	const pageSize = 1000
	for page := 1; ; page++ {
		query := url.Values{
			"name":     []string{recordName},
			"per_page": []string{strconv.Itoa(pageSize)},
			"page":     []string{strconv.Itoa(page)},
		}
		var response cloudflareEnvelope[[]dnsRecord]
		if err := c.request(ctx, http.MethodGet, "/zones/"+url.PathEscape(c.ZoneID)+"/dns_records?"+query.Encode(), nil, &response); err != nil {
			return nil, fmt.Errorf("list Cloudflare DNS records: %w", err)
		}
		for _, record := range response.Result {
			if (record.Type == "A" || record.Type == "AAAA") &&
				equalDNSName(record.Name, recordName) {
				records = append(records, record)
			}
		}
		if response.ResultInfo.TotalPages > 0 {
			if page >= response.ResultInfo.TotalPages {
				break
			}
		} else if len(response.Result) < pageSize {
			break
		}
	}
	return records, nil
}

func (c CloudflareClient) createRecord(ctx context.Context, record dnsRecord) error {
	var response cloudflareEnvelope[dnsRecord]
	if err := c.request(ctx, http.MethodPost, "/zones/"+url.PathEscape(c.ZoneID)+"/dns_records", record.payload(), &response); err != nil {
		return fmt.Errorf("create Cloudflare %s record for %s: %w", record.Type, record.Content, err)
	}
	return nil
}

func (c CloudflareClient) updateRecord(ctx context.Context, record dnsRecord) error {
	var response cloudflareEnvelope[dnsRecord]
	path := "/zones/" + url.PathEscape(c.ZoneID) + "/dns_records/" + url.PathEscape(record.ID)
	if err := c.request(ctx, http.MethodPut, path, record.payload(), &response); err != nil {
		return fmt.Errorf("set Cloudflare record %s to DNS-only: %w", record.ID, err)
	}
	return nil
}

func (c CloudflareClient) deleteRecord(ctx context.Context, id string) error {
	var response cloudflareEnvelope[json.RawMessage]
	path := "/zones/" + url.PathEscape(c.ZoneID) + "/dns_records/" + url.PathEscape(id)
	if err := c.request(ctx, http.MethodDelete, path, nil, &response); err != nil {
		return fmt.Errorf("delete stale Cloudflare record %s: %w", id, err)
	}
	return nil
}

func (c CloudflareClient) request(ctx context.Context, method, path string, body any, result any) error {
	baseURL := c.BaseURL
	if baseURL == "" {
		baseURL = cloudflareAPIURL
	}
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		bodyReader = bytes.NewReader(data)
	}
	request, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(baseURL, "/")+path, bodyReader)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+c.Token)
	request.Header.Set("Content-Type", "application/json")
	client := c.Client
	if client == nil {
		client = http.DefaultClient
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	if err != nil {
		return err
	}
	var envelope struct {
		Success bool `json:"success"`
		Errors  []struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(responseBody, &envelope); err != nil {
		return fmt.Errorf("Cloudflare API returned HTTP %s with invalid JSON", response.Status)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 || !envelope.Success {
		messages := make([]string, 0, len(envelope.Errors))
		for _, apiError := range envelope.Errors {
			messages = append(messages, fmt.Sprintf("%d: %s", apiError.Code, apiError.Message))
		}
		return fmt.Errorf("Cloudflare API HTTP %s: %s", response.Status, strings.Join(messages, "; "))
	}
	return json.Unmarshal(responseBody, result)
}

func equalDNSName(first, second string) bool {
	return strings.EqualFold(strings.TrimSuffix(first, "."), strings.TrimSuffix(second, "."))
}

func (record dnsRecord) payload() dnsRecordPayload {
	return dnsRecordPayload{
		Type: record.Type, Name: record.Name, Content: record.Content,
		TTL: record.TTL, Proxied: record.Proxied, Comment: record.Comment,
		Tags: record.Tags, Settings: record.Settings,
	}
}

func sameIPContent(first, second string) bool {
	firstIP, firstErr := netip.ParseAddr(first)
	secondIP, secondErr := netip.ParseAddr(second)
	return firstErr == nil && secondErr == nil && firstIP.Unmap() == secondIP.Unmap()
}
