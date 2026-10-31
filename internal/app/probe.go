package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"sync"
	"time"
)

type endpointProbeResult struct {
	Endpoint Endpoint
	Status   string
	Speed    float64
	Error    string
}

const (
	probeStatusPassed  = "passed"
	probeStatusFailed  = "failed"
	probeStatusDeleted = "deleted"
)

func ProbeEndpoint(ctx context.Context, endpoint Endpoint, config Config) error {
	target, err := url.Parse(config.ProbeURL)
	if err != nil {
		return err
	}
	query := target.Query()
	query.Set("bytes", strconv.FormatInt(config.ExpectedBytes, 10))
	target.RawQuery = query.Encode()

	dialer := &net.Dialer{Timeout: time.Duration(config.TimeoutMS) * time.Millisecond}
	transport := &http.Transport{
		DisableKeepAlives:   true,
		DisableCompression:  true,
		TLSHandshakeTimeout: time.Duration(config.TimeoutMS) * time.Millisecond,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			address := net.JoinHostPort(endpoint.IP.String(), strconv.Itoa(endpoint.Port))
			return dialer.DialContext(ctx, "tcp", address)
		},
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(config.TimeoutMS) * time.Millisecond,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return err
	}
	request.Header.Set("Accept-Encoding", "identity")
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected HTTP status: %s", response.Status)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, config.ExpectedBytes+1))
	if err != nil {
		return err
	}
	if int64(len(body)) != config.ExpectedBytes {
		return fmt.Errorf("expected %d bytes, received %d", config.ExpectedBytes, len(body))
	}
	return nil
}

func CheckEndpoints(
	ctx context.Context,
	endpoints []Endpoint,
	config Config,
	probe func(context.Context, Endpoint, Config) error,
	logger Logger,
) []endpointProbeResult {
	results := make([]endpointProbeResult, len(endpoints))
	for index, endpoint := range endpoints {
		results[index] = endpointProbeResult{
			Endpoint: endpoint,
			Status:   probeStatusFailed,
			Error:    "probe was not completed",
		}
	}
	var next int
	var mu sync.Mutex
	workerCount := min(config.ConcurrentRuns, len(endpoints))
	var workers sync.WaitGroup
	for range workerCount {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for {
				if ctx.Err() != nil {
					return
				}
				mu.Lock()
				if next >= len(endpoints) {
					mu.Unlock()
					return
				}
				index := next
				next++
				mu.Unlock()

				endpoint := endpoints[index]
				var lastError error
				var totalDuration time.Duration
				for trial := 1; trial <= config.Trials; trial++ {
					started := time.Now()
					err := probe(ctx, endpoint, config)
					duration := time.Since(started)
					if err != nil {
						reason := probeErrorReason(err)
						logger.Printf("[%d/%d] failed - %s: %s", trial, config.Trials, endpoint.IP, reason)
						lastError = err
						break
					}
					totalDuration += duration
					logger.Printf("[%d/%d] passed - %s", trial, config.Trials, endpoint.IP)
				}
				if lastError != nil {
					results[index].Error = probeErrorReason(lastError)
					continue
				}
				results[index].Status = probeStatusPassed
				results[index].Error = ""
				if totalDuration > 0 {
					results[index].Speed = float64(config.ExpectedBytes*int64(config.Trials)) /
						totalDuration.Seconds() / (1024 * 1024)
				}
			}
		}()
	}
	workers.Wait()

	return orderProbeResults(results)
}

func probeErrorReason(err error) string {
	var requestError *url.Error
	if errors.As(err, &requestError) {
		err = requestError.Err
	}
	return err.Error()
}

func orderProbeResults(results []endpointProbeResult) []endpointProbeResult {
	ranked := make([]endpointProbeResult, 0, len(results))
	failed := make([]endpointProbeResult, 0, len(results))
	for _, result := range results {
		if result.Status == probeStatusPassed {
			ranked = append(ranked, result)
		} else {
			failed = append(failed, result)
		}
	}
	sort.SliceStable(ranked, func(i, j int) bool {
		return ranked[i].Speed > ranked[j].Speed
	})
	ordered := append(ranked, failed...)
	return ordered
}
