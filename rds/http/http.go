// Copyright 2023 The Cloudprober Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/*
Package http implements a HTTP-based targets provider for cloudprober.
*/
package http

import (
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"sync"
	"time"

	"github.com/cloudprober/cloudprober/common/tlsconfig"
	"github.com/cloudprober/cloudprober/logger"
	configpb "github.com/cloudprober/cloudprober/rds/http/proto"
	pb "github.com/cloudprober/cloudprober/rds/proto"
	"github.com/cloudprober/cloudprober/rds/server/filter"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"
)

// DefaultProviderID is the povider id to use for this provider if a provider
// id is not configured explicitly.
const DefaultProviderID = "http"

var SupportedFilters = struct {
	RegexFilterKeys []string
	LabelsFilter    bool
}{
	[]string{"name"},
	true,
}

// lister implements HTTP-based targets lister.
type lister struct {
	mu        sync.RWMutex
	url       string
	format    configpb.ProviderConfig_Format
	resources []*pb.Resource
	client    *http.Client
	l         *logger.Logger

	cachedLastModified time.Time
	cachedEtag         string

	lastUpdated time.Time
}

func (ls *lister) lastModified() int64 {
	ls.mu.RLock()
	defer ls.mu.RUnlock()
	return ls.lastUpdated.Unix()
}

// listResources returns the last successfully parsed list of resources.
func (ls *lister) listResources(req *pb.ListResourcesRequest) (*pb.ListResourcesResponse, error) {
	ls.mu.RLock()
	defer ls.mu.RUnlock()

	// If there are no filters, return early.
	if len(req.GetFilter()) == 0 {
		return &pb.ListResourcesResponse{
			Resources:    append([]*pb.Resource{}, ls.resources...),
			LastModified: proto.Int64(ls.lastUpdated.Unix()),
		}, nil
	}

	allFilters, err := filter.ParseFilters(req.GetFilter(), SupportedFilters.RegexFilterKeys, "")
	if err != nil {
		return nil, err
	}
	nameFilter, labelsFilter := allFilters.RegexFilters["name"], allFilters.LabelsFilter

	// Allocate resources for response early but optimize for large number of
	// total resources.
	allocSize := len(ls.resources)
	if allocSize > 100 {
		allocSize = 100
	}
	resources := make([]*pb.Resource, 0, allocSize)

	for _, res := range ls.resources {
		if nameFilter != nil && !nameFilter.Match(res.GetName(), ls.l) {
			continue
		}
		if labelsFilter != nil && !labelsFilter.Match(res.GetLabels(), ls.l) {
			continue
		}
		resources = append(resources, res)
	}

	ls.l.Infof("httpListResources: returning %d resources out of %d", len(resources), len(ls.resources))
	return &pb.ListResourcesResponse{
		Resources:    resources,
		LastModified: proto.Int64(ls.lastUpdated.Unix()),
	}, nil
}

func (ls *lister) parseFileContent(b []byte) ([]*pb.Resource, error) {
	resources := &configpb.HttpResources{}

	switch ls.format {
	case configpb.ProviderConfig_TEXTPB:
		err := prototext.Unmarshal(b, resources)
		if err != nil {
			return nil, fmt.Errorf("http_provider(%s): error unmarshaling as text proto: %v", ls.url, err)
		}
		return resources.GetResource(), nil
	case configpb.ProviderConfig_JSON:
		err := protojson.Unmarshal(b, resources)
		if err != nil {
			return nil, fmt.Errorf("http_provider(%s): error unmarshaling as JSON: %v", ls.url, err)
		}
		return resources.GetResource(), nil
	}

	return nil, fmt.Errorf("http_provider(%s): unknown format - %v", ls.url, ls.format)
}

func (ls *lister) createRequest() (*http.Request, error) {
	ls.mu.Lock()
	defer ls.mu.Unlock()

	req, err := http.NewRequest("GET", ls.url, http.NoBody)
	if err != nil {
		return nil, err
	}

	if t := ls.cachedLastModified; !t.IsZero() {
		req.Header.Set("If-Modified-Since", t.Format(http.TimeFormat))
	}
	if e := ls.cachedEtag; e != "" {
		req.Header.Set("If-None-Match", e)
	}

	return req, nil
}

func (ls *lister) refresh() error {
	req, err := ls.createRequest()
	if err != nil {
		return err
	}

	res, err := ls.client.Do(req)
	if err != nil {
		return fmt.Errorf("http_provider(%s): http request failed: %w", ls.url, err)
	}

	if res.StatusCode == 304 { // Not Modified
		ls.l.Infof("http_provider(%s): Remote file is not modified.", ls.url)
		return nil
	}

	if res.StatusCode != 200 {
		return fmt.Errorf("http_provider(%s): remote server returned %s", ls.url, res.Status)
	}

	b, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}

	resources, err := ls.parseFileContent(b)
	if err != nil {
		return err
	}

	ls.mu.Lock()
	defer ls.mu.Unlock()

	ls.lastUpdated = time.Now()
	ls.resources = resources

	t, err := http.ParseTime(res.Header.Get("Last-Modified"))
	if err != nil {
		ls.cachedLastModified = time.Time{}
	} else {
		ls.cachedLastModified = t
	}
	ls.cachedEtag = res.Header.Get("ETag")

	ls.l.Infof("http_provider(%s): Read %d resources.", ls.url, len(ls.resources))
	return nil
}

// newLister creates a new HTTP-based targets lister.
func newLister(url string, c *configpb.ProviderConfig, client *http.Client, l *logger.Logger) (*lister, error) {
	format := c.GetFormat()

	ls := &lister{
		url:    url,
		format: format,
		client: client,
		l:      l,
	}

	reEvalSec := c.GetReEvalSec()
	if reEvalSec == 0 {
		return ls, ls.refresh()
	}

	reEvalInterval := time.Duration(reEvalSec) * time.Second
	go func() {
		if err := ls.refresh(); err != nil {
			l.Error(err.Error())
		}
		// Introduce a random delay between 0-reEvalInterval before
		// starting the refresh loop. If there are multiple cloudprober
		// instances, this will make sure that each instance refreshes
		// at a different point of time.
		rand.Seed(time.Now().UnixNano())
		randomDelaySec := rand.Intn(int(reEvalInterval.Seconds()))
		time.Sleep(time.Duration(randomDelaySec) * time.Second)
		for range time.Tick(reEvalInterval) {
			if err := ls.refresh(); err != nil {
				l.Error(err.Error())
			}
		}
	}()

	return ls, nil
}

func responseWithCacheCheck(ls *lister, req *pb.ListResourcesRequest) (*pb.ListResourcesResponse, error) {
	if req.GetIfModifiedSince() == 0 {
		return ls.listResources(req)
	}

	if lastModified := ls.lastModified(); lastModified <= req.GetIfModifiedSince() {
		return &pb.ListResourcesResponse{
			LastModified: proto.Int64(lastModified),
		}, nil
	}

	return ls.listResources(req)
}

// ListResources returns the list of resources based on the given request.
func (p *Provider) ListResources(req *pb.ListResourcesRequest) (*pb.ListResourcesResponse, error) {
	url := req.GetResourcePath()
	if url != "" {
		ls := p.listers[url]
		if ls == nil {
			return nil, fmt.Errorf("URL %s is not available on this server", url)
		}
		return responseWithCacheCheck(ls, req)
	}

	// Avoid append and another allocation if there is only one lister, most
	// common use case.
	if len(p.listers) == 1 {
		for _, ls := range p.listers {
			return responseWithCacheCheck(ls, req)
		}
	}

	// If we are working with multiple listers, it's slightly more complicated.
	// In that case we need to return all the listers' resources even if only one
	// of them has changed.
	//
	// Get the latest last-modified.
	lastModified := int64(0)
	for _, ls := range p.listers {
		listerLastModified := ls.lastModified()
		if lastModified < listerLastModified {
			lastModified = listerLastModified
		}
	}
	resp := &pb.ListResourcesResponse{
		LastModified: proto.Int64(lastModified),
	}

	// if nothing changed since req.IfModifiedSince, return early.
	if req.GetIfModifiedSince() != 0 && lastModified <= req.GetIfModifiedSince() {
		return resp, nil
	}

	var result []*pb.Resource
	for _, url := range p.urls {
		res, err := p.listers[url].listResources(req)
		if err != nil {
			return nil, err
		}
		result = append(result, res.Resources...)
	}
	resp.Resources = result
	return resp, nil
}

// Provider provides a HTTP-based targets provider for RDS. It implements the
// RDS server's Provider interface.
type Provider struct {
	urls    []string
	listers map[string]*lister
}

func createHttpClient(c *configpb.ProviderConfig) (*http.Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()

	if c.GetTlsConfig() != nil {
		tlsConfig := &tls.Config{}
		if err := tlsconfig.UpdateTLSConfig(tlsConfig, c.GetTlsConfig()); err != nil {
			return nil, err
		}
		transport.TLSClientConfig = tlsConfig
	}

	return &http.Client{
		Timeout:   time.Duration(c.GetTimeoutSec()) * time.Second,
		Transport: transport,
	}, nil
}

// New creates a HTTP (http) provider for RDS server, based on the
// provided config.
func New(c *configpb.ProviderConfig, l *logger.Logger) (*Provider, error) {
	urls := c.GetUrl()
	p := &Provider{
		urls:    urls,
		listers: make(map[string]*lister),
	}

	client, err := createHttpClient(c)
	if err != nil {
		return nil, err
	}

	for _, url := range urls {
		lister, err := newLister(url, c, client, l)
		if err != nil {
			return nil, err
		}
		p.listers[url] = lister
	}

	return p, nil
}
