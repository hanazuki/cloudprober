// Copyright 2020-2021 The Cloudprober Authors.
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
Package http implements a HTTP-based targets for cloudprober.
*/
package http

import (
	"context"

	"github.com/cloudprober/cloudprober/internal/rds/client"
	client_configpb "github.com/cloudprober/cloudprober/internal/rds/client/proto"
	"github.com/cloudprober/cloudprober/internal/rds/http"
	http_configpb "github.com/cloudprober/cloudprober/internal/rds/http/proto"
	rdspb "github.com/cloudprober/cloudprober/internal/rds/proto"
	"github.com/cloudprober/cloudprober/logger"
	configpb "github.com/cloudprober/cloudprober/targets/http/proto"
	dnsRes "github.com/cloudprober/cloudprober/targets/resolver"
	"google.golang.org/protobuf/proto"
)

// New returns new HTTP targets.
func New(opts *configpb.TargetsConf, res *dnsRes.Resolver, l *logger.Logger) (*client.Client, error) {
	lister, err := http.New(&http_configpb.ProviderConfig{
		Url:        []string{opts.GetUrl()},
		TlsConfig:  opts.GetTlsConfig(),
		Format:     opts.Format,
		TimeoutSec: proto.Int32(opts.GetTimeoutSec()),
		ReEvalSec:  proto.Int32(opts.GetReEvalSec()),
	}, l)
	if err != nil {
		return nil, err
	}

	clientConf := &client_configpb.ClientConf{
		Request:   &rdspb.ListResourcesRequest{Filter: opts.GetFilter()},
		ReEvalSec: proto.Int32(1),
	}

	return client.New(clientConf, func(_ context.Context, req *rdspb.ListResourcesRequest) (*rdspb.ListResourcesResponse, error) {
		return lister.ListResources(req)
	}, l)
}
