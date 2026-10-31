package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const cloudflareAPIURL = "https://api.cloudflare.com/client/v4"

const (
	cloudflareMaxAttempts        = 3
	cloudflareRetryDelay         = 250 * time.Millisecond
	cloudflareMaxRetry           = 5 * time.Second
	cloudflareMaxBatchOperations = 200
)

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

type dnsRecordPatch struct {
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

type dnsRecordDelete struct {
	ID string `json:"id"`
}

type dnsBatchPayload struct {
	Deletes []dnsRecordDelete  `json:"deletes,omitempty"`
	Patches []dnsRecordPatch   `json:"patches,omitempty"`
	Posts   []dnsRecordPayload `json:"posts,omitempty"`
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

type retryableCloudflareError struct {
	err        error
	retryAfter time.Duration
}

func (e retryableCloudflareError) Error() string {
	return e.err.Error()
}

func (e retryableCloudflareError) Unwrap() error {
	return e.err
}

func (c CloudflareClient) ReconcileDNS(ctx context.Context, recordName string, endpoints []Endpoint) error {
	if len(endpoints) == 0 {
		return fmt.Errorf("refusing to update DNS with an empty endpoint set")
	}
	_, err := c.ReconcileDNSWithDeleted(ctx, recordName, endpoints)
	return err
}

func (c CloudflareClient) ReconcileDNSWithDeleted(ctx context.Context, recordName string, endpoints []Endpoint) ([]Endpoint, error) {
	if strings.TrimSpace(c.ZoneID) == "" {
		return nil, fmt.Errorf("Cloudflare zoneId is required")
	}
	if strings.TrimSpace(recordName) == "" {
		return nil, fmt.Errorf("Cloudflare recordName is required")
	}
	if strings.TrimSpace(c.Token) == "" {
		return nil, fmt.Errorf("Cloudflare API token is empty")
	}
	desired := make([]dnsRecordPayload, 0, len(endpoints))
	seen := make(map[string]struct{}, len(endpoints))
	for _, endpoint := range endpoints {
		ip := endpoint.IP.Unmap()
		if endpoint.Port != 443 || !ip.IsValid() {
			continue
		}
		recordType := "A"
		if ip.Is6() {
			recordType = "AAAA"
		}
		content := ip.String()
		key := recordType + ":" + content
		if _, found := seen[key]; found {
			continue
		}
		seen[key] = struct{}{}
		desired = append(desired, dnsRecord{
			Type: recordType, Name: recordName, Content: content, TTL: 1, Proxied: false,
		}.payload())
	}
	if len(endpoints) > 0 && len(desired) == 0 {
		return nil, fmt.Errorf("refusing to update DNS: no valid port 443 IP addresses")
	}

	path := "/zones/" + url.PathEscape(c.ZoneID) + "/dns_records/batch"
	var originalRecords []dnsRecord
	originalRecordsLoaded := false
	changesApplied := false
	for attempt := 1; attempt <= cloudflareMaxAttempts; attempt++ {
		records, err := c.listRecords(ctx, recordName)
		if err != nil {
			if !isRetryableCloudflareError(err) || attempt == cloudflareMaxAttempts {
				if changesApplied {
					return removedDNSAddresses(originalRecords, desired), err
				}
				return nil, err
			}
			if err := waitCloudflareRetry(ctx, err, attempt); err != nil {
				if changesApplied {
					return removedDNSAddresses(originalRecords, desired), err
				}
				return nil, err
			}
			continue
		}
		if !originalRecordsLoaded {
			originalRecords = append([]dnsRecord(nil), records...)
			originalRecordsLoaded = true
		}

		patches, deletes, remaining := buildDNSChanges(records, desired)
		retryErr := error(nil)
		for _, batch := range buildDNSChangeBatches(patches, deletes) {
			var response cloudflareEnvelope[json.RawMessage]
			err := c.request(ctx, http.MethodPost, path, batch, &response)
			if err != nil {
				retryErr = err
				break
			}
		}
		if retryErr == nil {
			changesApplied = true
			for offset := 0; offset < len(remaining); offset += cloudflareMaxBatchOperations {
				end := min(offset+cloudflareMaxBatchOperations, len(remaining))
				var response cloudflareEnvelope[json.RawMessage]
				retryErr = c.request(
					ctx,
					http.MethodPost,
					path,
					dnsBatchPayload{Posts: remaining[offset:end]},
					&response,
				)
				if retryErr != nil {
					break
				}
			}
		}
		if retryErr == nil {
			return removedDNSAddresses(originalRecords, desired), nil
		}
		if !isRetryableCloudflareError(retryErr) || attempt == cloudflareMaxAttempts {
			if changesApplied {
				return removedDNSAddresses(originalRecords, desired), fmt.Errorf("reconcile Cloudflare DNS records for %s: %w", recordName, retryErr)
			}
			return nil, fmt.Errorf("reconcile Cloudflare DNS records for %s: %w", recordName, retryErr)
		}
		if err := waitCloudflareRetry(ctx, retryErr, attempt); err != nil {
			if changesApplied {
				return removedDNSAddresses(originalRecords, desired), fmt.Errorf("retry Cloudflare DNS records for %s: %w", recordName, err)
			}
			return nil, fmt.Errorf("retry Cloudflare DNS records for %s: %w", recordName, err)
		}
	}
	return nil, fmt.Errorf("reconcile Cloudflare DNS records for %s: retry attempts exhausted", recordName)
}

func buildDNSChanges(
	records []dnsRecord,
	desired []dnsRecordPayload,
) ([]dnsRecordPatch, []dnsRecordDelete, []dnsRecordPayload) {
	sortedRecords := append([]dnsRecord(nil), records...)
	sort.Slice(sortedRecords, func(i, j int) bool {
		return sortedRecords[i].ID < sortedRecords[j].ID
	})
	usedDesired := make([]bool, len(desired))
	usedRecords := make([]bool, len(sortedRecords))
	assignments := make([]int, len(sortedRecords))
	for i := range assignments {
		assignments[i] = -1
	}

	for recordIndex, record := range sortedRecords {
		for desiredIndex, target := range desired {
			if usedDesired[desiredIndex] {
				continue
			}
			if record.Type == target.Type &&
				normalizedDNSContent(record.Content) == normalizedDNSContent(target.Content) {
				usedRecords[recordIndex] = true
				usedDesired[desiredIndex] = true
				assignments[recordIndex] = desiredIndex
				break
			}
		}
	}

	for recordIndex, record := range sortedRecords {
		if usedRecords[recordIndex] {
			continue
		}
		desiredIndex := -1
		for index := range desired {
			if !usedDesired[index] && desired[index].Type == record.Type {
				desiredIndex = index
				break
			}
		}
		if desiredIndex < 0 {
			continue
		}
		assignments[recordIndex] = desiredIndex
		usedRecords[recordIndex] = true
		usedDesired[desiredIndex] = true
	}

	patches := make([]dnsRecordPatch, 0)
	deletes := make([]dnsRecordDelete, 0)
	for recordIndex, desiredIndex := range assignments {
		if desiredIndex < 0 {
			deletes = append(deletes, dnsRecordDelete{ID: sortedRecords[recordIndex].ID})
			continue
		}
		record := sortedRecords[recordIndex]
		target := desired[desiredIndex]
		patches = append(patches, dnsRecordPatch{
			ID:       record.ID,
			Type:     target.Type,
			Name:     target.Name,
			Content:  target.Content,
			TTL:      target.TTL,
			Proxied:  target.Proxied,
			Comment:  target.Comment,
			Tags:     target.Tags,
			Settings: target.Settings,
		})
	}

	remaining := make([]dnsRecordPayload, 0)
	for index, target := range desired {
		if !usedDesired[index] {
			remaining = append(remaining, target)
		}
	}
	return patches, deletes, remaining
}

func buildDNSChangeBatches(patches []dnsRecordPatch, deletes []dnsRecordDelete) []dnsBatchPayload {
	batches := make([]dnsBatchPayload, 0)
	for patchOffset, deleteOffset := 0, 0; patchOffset < len(patches) || deleteOffset < len(deletes); {
		patchEnd := min(patchOffset+cloudflareMaxBatchOperations, len(patches))
		patchCount := patchEnd - patchOffset
		deleteEnd := min(
			deleteOffset+cloudflareMaxBatchOperations-patchCount,
			len(deletes),
		)
		batches = append(batches, dnsBatchPayload{
			Patches: patches[patchOffset:patchEnd],
			Deletes: deletes[deleteOffset:deleteEnd],
		})
		patchOffset = patchEnd
		deleteOffset = deleteEnd
	}
	return batches
}

func removedDNSAddresses(records []dnsRecord, desired []dnsRecordPayload) []Endpoint {
	retained := make(map[string]struct{}, len(desired))
	for _, record := range desired {
		retained[record.Type+":"+normalizedDNSContent(record.Content)] = struct{}{}
	}
	removed := make(map[netip.Addr]struct{})
	for _, record := range records {
		if _, remains := retained[record.Type+":"+normalizedDNSContent(record.Content)]; remains {
			continue
		}
		ip, err := netip.ParseAddr(record.Content)
		if err == nil {
			removed[ip.Unmap()] = struct{}{}
		}
	}
	endpoints := make([]Endpoint, 0, len(removed))
	for ip := range removed {
		endpoints = append(endpoints, Endpoint{IP: ip, Port: 443})
	}
	sort.Slice(endpoints, func(i, j int) bool {
		return endpoints[i].IP.Compare(endpoints[j].IP) < 0
	})
	return endpoints
}

func normalizedDNSContent(content string) string {
	ip, err := netip.ParseAddr(content)
	if err != nil {
		return content
	}
	return ip.Unmap().String()
}

func (c CloudflareClient) CountRecordsExcludingHostname(ctx context.Context, hostname string) (int, error) {
	if strings.TrimSpace(c.ZoneID) == "" {
		return 0, fmt.Errorf("Cloudflare zoneId is required")
	}
	if strings.TrimSpace(hostname) == "" {
		return 0, fmt.Errorf("Cloudflare recordName is required")
	}
	if strings.TrimSpace(c.Token) == "" {
		return 0, fmt.Errorf("Cloudflare API token is empty")
	}

	const pageSize = 1000
	recordCount := 0
	for page := 1; ; page++ {
		query := url.Values{
			"per_page": []string{strconv.Itoa(pageSize)},
			"page":     []string{strconv.Itoa(page)},
		}
		var response cloudflareEnvelope[[]dnsRecord]
		path := "/zones/" + url.PathEscape(c.ZoneID) + "/dns_records?" + query.Encode()
		if err := c.requestWithRetry(ctx, http.MethodGet, path, nil, &response); err != nil {
			return 0, fmt.Errorf("count Cloudflare DNS records: %w", err)
		}
		for _, record := range response.Result {
			if !equalDNSName(record.Name, hostname) {
				recordCount++
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
	return recordCount, nil
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
		if err := c.requestWithRetry(ctx, http.MethodGet, "/zones/"+url.PathEscape(c.ZoneID)+"/dns_records?"+query.Encode(), nil, &response); err != nil {
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
		if ctx.Err() == nil {
			return retryableCloudflareError{err: err}
		}
		return err
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	if err != nil {
		if ctx.Err() == nil {
			return retryableCloudflareError{err: err}
		}
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
		if response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= 500 {
			return retryableCloudflareError{
				err:        fmt.Errorf("Cloudflare API HTTP %s returned invalid JSON", response.Status),
				retryAfter: parseRetryAfter(response.Header.Get("Retry-After"), time.Now()),
			}
		}
		if response.StatusCode >= 200 && response.StatusCode < 300 {
			return retryableCloudflareError{
				err: fmt.Errorf("Cloudflare API HTTP %s returned invalid JSON", response.Status),
			}
		}
		return fmt.Errorf("Cloudflare API returned HTTP %s with invalid JSON", response.Status)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 || !envelope.Success {
		messages := make([]string, 0, len(envelope.Errors))
		for _, apiError := range envelope.Errors {
			messages = append(messages, fmt.Sprintf("%d: %s", apiError.Code, apiError.Message))
		}
		apiErr := fmt.Errorf("Cloudflare API HTTP %s: %s", response.Status, strings.Join(messages, "; "))
		if response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= 500 {
			return retryableCloudflareError{
				err: apiErr, retryAfter: parseRetryAfter(response.Header.Get("Retry-After"), time.Now()),
			}
		}
		return apiErr
	}
	return json.Unmarshal(responseBody, result)
}

func (c CloudflareClient) requestWithRetry(ctx context.Context, method, path string, body any, result any) error {
	for attempt := 1; attempt <= cloudflareMaxAttempts; attempt++ {
		err := c.request(ctx, method, path, body, result)
		if err == nil {
			return nil
		}
		if !isRetryableCloudflareError(err) || attempt == cloudflareMaxAttempts {
			return err
		}
		if err := waitCloudflareRetry(ctx, err, attempt); err != nil {
			return err
		}
	}
	return fmt.Errorf("Cloudflare API retry attempts exhausted")
}

func isRetryableCloudflareError(err error) bool {
	var retryable retryableCloudflareError
	return errors.As(err, &retryable)
}

func waitCloudflareRetry(ctx context.Context, err error, attempt int) error {
	delay := cloudflareRetryDelay * time.Duration(1<<(attempt-1))
	var retryable retryableCloudflareError
	if errors.As(err, &retryable) && retryable.retryAfter > delay {
		delay = retryable.retryAfter
	}
	if delay > cloudflareMaxRetry {
		delay = cloudflareMaxRetry
	}

	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func parseRetryAfter(value string, now time.Time) time.Duration {
	if seconds, err := strconv.Atoi(strings.TrimSpace(value)); err == nil && seconds >= 0 {
		return time.Duration(seconds) * time.Second
	}
	if retryAt, err := http.ParseTime(value); err == nil {
		delay := retryAt.Sub(now)
		if delay > 0 {
			return delay
		}
	}
	return 0
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
