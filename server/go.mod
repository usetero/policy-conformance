module github.com/usetero/policy-conformance/server

go 1.24.0

require (
	github.com/usetero/policy-go v1.3.5
	google.golang.org/grpc v1.79.1
	google.golang.org/protobuf v1.36.11
)

replace github.com/usetero/policy-go => ../../policy-go

require (
	github.com/flier/gohs v1.2.3 // indirect
	go.opentelemetry.io/proto/otlp v1.9.0 // indirect
	golang.org/x/net v0.48.0 // indirect
	golang.org/x/sys v0.39.0 // indirect
	golang.org/x/text v0.32.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20260120221211-b8f7ae30c516 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260120174246-409b4a993575 // indirect
)
