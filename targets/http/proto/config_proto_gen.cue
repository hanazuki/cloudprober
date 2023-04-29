package proto

import (
	"github.com/cloudprober/cloudprober/rds/proto"
	proto_1 "github.com/cloudprober/cloudprober/rds/http/proto"
	proto_5 "github.com/cloudprober/cloudprober/common/tlsconfig/proto"
)

#TargetsConf: {
	url?: string @protobuf(1,string)
	filter?: [...proto.#Filter] @protobuf(2,.cloudprober.rds.Filter)
	format?:     proto_1.#ProviderConfig.#Format @protobuf(3,.cloudprober.rds.http.ProviderConfig.Format)
	tlsConfig?:  proto_5.#TLSConfig              @protobuf(4,.cloudprober.tlsconfig.TLSConfig,name=tls_config)
	reEvalSec?:  int32                           @protobuf(5,int32,name=re_eval_sec)
	timeoutSec?: int32                           @protobuf(6,int32,name=timeout_sec)
}
