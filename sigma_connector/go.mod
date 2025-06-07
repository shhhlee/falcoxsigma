module github.com/yourorg/falco-sigma-pipeline/sigma_connector

go 1.23.0

toolchain go1.24.3

require (
	github.com/markuskont/go-sigma-rule-engine v0.3.0
	go.opentelemetry.io/proto/otlp v1.7.0
	google.golang.org/grpc v1.73.0
)

require (
	github.com/gobwas/glob v0.2.3 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.26.3 // indirect
	github.com/rogpeppe/go-internal v1.14.1 // indirect
	golang.org/x/net v0.40.0 // indirect
	golang.org/x/sys v0.33.0 // indirect
	golang.org/x/text v0.25.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20250528174236-200df99c418a // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250528174236-200df99c418a // indirect
	google.golang.org/protobuf v1.36.6 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
)

replace google.golang.org/genproto/googleapis => google.golang.org/genproto v0.0.0-20250519155744-55703ea1f237
