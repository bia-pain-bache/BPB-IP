package app

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"
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
) []Endpoint {
	results := make([]bool, len(endpoints))
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
				passed := true
				for trial := 1; trial <= config.Trials; trial++ {
					err := probe(ctx, endpoint, config)
					if err != nil {
						logger.Printf("%s trial %d/%d: failed: %v", endpoint, trial, config.Trials, err)
						passed = false
						break
					}
					logger.Printf("%s trial %d/%d: passed", endpoint, trial, config.Trials)
				}
				results[index] = passed
			}
		}()
	}
	workers.Wait()

	var working []Endpoint
	for index, passed := range results {
		if passed {
			working = append(working, endpoints[index])
		}
	}
	return working
}
