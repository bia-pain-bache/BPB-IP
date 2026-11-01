package app

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type Endpoint struct {
	IP   netip.Addr
	Port int
}

func (e Endpoint) String() string {
	return net.JoinHostPort(e.IP.String(), strconv.Itoa(e.Port))
}

func ParseEndpoints(contents string) ([]Endpoint, error) {
	var endpoints []Endpoint
	seen := make(map[Endpoint]struct{})
	for lineNumber, rawLine := range strings.Split(contents, "\n") {
		line := strings.TrimSpace(strings.SplitN(rawLine, "#", 2)[0])
		if line == "" {
			continue
		}

		endpoint, err := parseEndpoint(line)
		if err != nil {
			return nil, fmt.Errorf("invalid endpoint on line %d: %s", lineNumber+1, rawLine)
		}
		endpoint.IP = endpoint.IP.Unmap()
		if _, exists := seen[endpoint]; !exists {
			seen[endpoint] = struct{}{}
			endpoints = append(endpoints, endpoint)
		}
	}
	return endpoints, nil
}

func parseEndpoint(line string) (Endpoint, error) {
	fields := strings.Fields(line)
	ipText, portText := "", ""
	switch len(fields) {
	case 1:
		if address, err := netip.ParseAddr(strings.Trim(fields[0], "[]")); err == nil {
			return Endpoint{IP: address, Port: 443}, nil
		}
		host, port, err := net.SplitHostPort(fields[0])
		if err != nil {
			return Endpoint{}, err
		}
		ipText, portText = host, port
	case 2:
		ipText, portText = strings.Trim(fields[0], "[]"), fields[1]
	default:
		return Endpoint{}, fmt.Errorf("expected an IP address with an optional port")
	}

	address, err := netip.ParseAddr(ipText)
	if err != nil {
		return Endpoint{}, err
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return Endpoint{}, fmt.Errorf("invalid port %q", portText)
	}
	return Endpoint{IP: address, Port: port}, nil
}

func CollectEndpoints(
	ctx context.Context,
	localContents string,
	config Config,
	logger Logger,
	resolvers ...domainResolver,
) []Endpoint {
	return CollectEndpointsWithArchive(ctx, localContents, "", config, logger, resolvers...)
}

func CollectEndpointsWithArchive(
	ctx context.Context,
	localContents string,
	archiveContents string,
	config Config,
	logger Logger,
	resolvers ...domainResolver,
) []Endpoint {
	resolveDomain := domainResolver(net.DefaultResolver.LookupIPAddr)
	if len(resolvers) > 0 && resolvers[0] != nil {
		resolveDomain = resolvers[0]
	}
	client := &http.Client{
		Timeout: time.Duration(config.FetchTimeoutMS) * time.Millisecond,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return collectEndpointsWithArchive(ctx, localContents, archiveContents, config, logger, resolveDomain, client)
}

func collectEndpoints(
	ctx context.Context,
	localContents string,
	config Config,
	logger Logger,
	resolveDomain domainResolver,
	client *http.Client,
) []Endpoint {
	return collectEndpointsWithArchive(ctx, localContents, "", config, logger, resolveDomain, client)
}

func collectEndpointsWithArchive(
	ctx context.Context,
	localContents string,
	archiveContents string,
	config Config,
	logger Logger,
	resolveDomain domainResolver,
	client *http.Client,
) []Endpoint {
	var inputs [][]Endpoint
	local, err := ParseEndpoints(localContents)
	logSource(logger, "list.txt", local, err)
	if err == nil {
		inputs = append(inputs, local)
	}
	if config.IncludeArchive {
		archived, err := ParseEndpoints(archiveContents)
		logSource(logger, "archive.txt", archived, err)
		if err == nil {
			inputs = append(inputs, archived)
		}
	}

	for index, source := range config.SourceURLs {
		endpoints, err := fetchEndpoints(ctx, client, source, config)
		label := source
		if strings.TrimSpace(label) == "" {
			label = fmt.Sprintf("sourceUrls[%d] (empty)", index)
		}
		logSource(logger, label, endpoints, err)
		if err == nil {
			inputs = append(inputs, endpoints)
		}
	}
	for _, rawDomain := range config.SourceDomains {
		domain := strings.TrimSpace(rawDomain)
		if domain == "" {
			logger.Printf("sourceDomains: empty domain entry")
			continue
		}
		addresses, err := resolveDomain(ctx, domain)
		if err != nil {
			logger.Printf("%s: DNS resolution failed: %v", domain, err)
			continue
		}
		endpoints := make([]Endpoint, 0, len(addresses))
		for _, address := range addresses {
			ip, ok := netip.AddrFromSlice(address.IP)
			if ok {
				endpoints = append(endpoints, Endpoint{IP: ip.Unmap(), Port: 443})
			}
		}
		logSource(logger, domain, endpoints, nil)
		inputs = append(inputs, endpoints)
	}

	return filterPort(MergeEndpoints(inputs...), 443)
}

func fetchEndpoints(ctx context.Context, client *http.Client, rawURL string, config Config) ([]Endpoint, error) {
	parsedURL, err := url.ParseRequestURI(rawURL)
	if err != nil || parsedURL.Scheme != "https" || parsedURL.Hostname() == "" {
		return nil, fmt.Errorf("source URL must be a valid HTTPS URL")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsedURL.String(), nil)
	if err != nil {
		return nil, err
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %s", response.Status)
	}
	const maxSourceBytes = 8 << 20
	body, err := io.ReadAll(io.LimitReader(response.Body, maxSourceBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxSourceBytes {
		return nil, fmt.Errorf("source exceeds %d bytes", maxSourceBytes)
	}
	return ParseEndpoints(string(body))
}

func logSource(logger Logger, name string, endpoints []Endpoint, err error) {
	if err != nil {
		logger.Printf("%s: failed: %v", name, err)
		return
	}
	for _, endpoint := range endpoints {
		if endpoint.Port == 443 {
			return
		}
	}
	logger.Printf("%s: no port 443 endpoints found", name)
}

func MergeEndpoints(groups ...[]Endpoint) []Endpoint {
	seen := make(map[Endpoint]struct{})
	var result []Endpoint
	for _, group := range groups {
		for _, endpoint := range group {
			if _, exists := seen[endpoint]; exists {
				continue
			}
			seen[endpoint] = struct{}{}
			result = append(result, endpoint)
		}
	}
	return result
}

func filterPort(endpoints []Endpoint, port int) []Endpoint {
	result := make([]Endpoint, 0, len(endpoints))
	for _, endpoint := range endpoints {
		if endpoint.Port == port {
			result = append(result, endpoint)
		}
	}
	return result
}
