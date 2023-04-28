package proto

import (
	"github.com/cloudprober/cloudprober/common/tlsconfig/proto"
	proto_1 "github.com/cloudprober/cloudprober/rds/proto"
)

// HTTP provider config.
#ProviderConfig: {
	// HTTP URL to remote file that contains resources in either textproto or json format.
	// Example in textproto format:
	//
	// resource {
	//   name: "switch-xx-01"
	//   ip: "10.11.112.3"
	//   port: 8080
	//   labels {
	//     key: "device_type"
	//     value: "switch"
	//   }
	// }
	// resource {
	//   name: "switch-yy-01"
	//   ip: "10.16.110.12"
	//   port: 8080
	// }
	url?: [...string] @protobuf(1,string)

	#Format: {
		// UNSPECIFIED = 0;  // Determine format by content negotiation -- Not yet implemented
		"TEXTPB"// Text proto format (application/x-textpb).
		#enumValue: 1
	} | {
		"JSON"// JSON proto format (application/json).
		#enumValue: 2
	}

	#Format_value: {
		TEXTPB: 1
		JSON:   2
	}

	format?: #Format @protobuf(2,Format) // Expected response format -- Required for now

	// TLS config to authenticate communication with the remote server.
	tlsConfig?:  proto.#TLSConfig @protobuf(3,tlsconfig.TLSConfig,name=tls_config)
	timeoutSec?: int32            @protobuf(4,int32,name=timeout_sec)

	// How often resources should be evaluated/expanded.
	reEvalSec?: int32 @protobuf(99,int32,name=re_eval_sec,"default=300") // default 5 min
}

#HttpResources: {
	resource?: [...proto_1.#Resource] @protobuf(1,.cloudprober.rds.Resource)
}
