# Envoy External Auth Service

Clean architecture implementation of Envoy External Authorization service in Go.

## Architecture

The project follows Clean Architecture principles with clear separation of concerns:

```
src/
├── domain/              # Enterprise business rules
│   ├── auth/           # Authorization domain entities and interfaces
│   └── logger/         # Logging domain interface
├── application/        # Application business rules
│   └── usecase/        # Use cases (business logic)
├── infrastructure/     # Frameworks & drivers
│   ├── config/         # Configuration management
│   ├── grpc/           # gRPC service implementations
│   └── logging/        # Logging implementations
├── presentation/       # Interface adapters
│   └── server/         # Server setup and lifecycle
└── cmd/               # Application entry points
    └── authserver/    # Main application
```

## Features

- **L7 (HTTP) Authorization**: Implements Envoy External Authorization API v3
- **L3-L4 (Network) Processing**: Implements Envoy External Processing API v3
- **Clean Architecture**: Separation of concerns with clear boundaries
- **Structured Logging**: JSON and text format support
- **Graceful Shutdown**: Proper cleanup on termination
- **Health Checks**: gRPC health check support
- **Reflection**: gRPC reflection for debugging

## Configuration

Edit `config.json`:

```json
{
  "server": {
    "grpc_port": 9001,
    "host": "0.0.0.0"
  },
  "log": {
    "level": "info",
    "json_format": false
  }
}
```

### Log Levels
- `debug`: Detailed debugging information
- `info`: General informational messages
- `warn`: Warning messages
- `error`: Error messages

## Building

```bash
cd src
go build -o authserver ./cmd/authserver
```

## Running

```bash
./authserver -config config.json
```

Or from the src directory:

```bash
go run ./cmd/authserver -config config.json
```

## Current Behavior

The service currently implements an "allow all" policy:
- Logs all authorization requests with detailed information
- Always allows requests to proceed
- Works on both L3-L4 (network) and L7 (HTTP) levels

## Extending

To implement custom authorization logic:

1. Create a new authorizer in `application/usecase/`
2. Implement the `auth.Authorizer` interface
3. Update `cmd/authserver/main.go` to use your authorizer

Example:

```go
type CustomAuthorizer struct {
    logger logger.Logger
}

func (a *CustomAuthorizer) Authorize(ctx context.Context, req *auth.AuthRequest) (*auth.AuthResponse, error) {
    // Your custom logic here
    if req.SourceIP == "192.168.1.100" {
        return &auth.AuthResponse{
            Decision: auth.DecisionDeny,
            Reason:   "IP blocked",
            DeniedMessage: "Access denied",
        }, nil
    }
    
    return &auth.AuthResponse{
        Decision: auth.DecisionAllow,
        Reason:   "Custom policy allows",
    }, nil
}
```

## Integration with Envoy

### L7 (HTTP) Authorization

Add to your Envoy configuration:

```yaml
http_filters:
  - name: envoy.filters.http.ext_authz
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
      grpc_service:
        envoy_grpc:
          cluster_name: ext_authz
        timeout: 0.5s
      transport_api_version: V3

clusters:
  - name: ext_authz
    type: STRICT_DNS
    typed_extension_protocol_options:
      envoy.extensions.upstreams.http.v3.HttpProtocolOptions:
        "@type": type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions
        explicit_http_config:
          http2_protocol_options: {}
    load_assignment:
      cluster_name: ext_authz
      endpoints:
        - lb_endpoints:
            - endpoint:
                address:
                  socket_address:
                    address: 127.0.0.1
                    port_value: 9001
```

### L3-L4 (Network) Processing

Add to your Envoy configuration:

```yaml
http_filters:
  - name: envoy.filters.http.ext_proc
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.ext_proc.v3.ExternalProcessor
      grpc_service:
        envoy_grpc:
          cluster_name: ext_proc
        timeout: 0.5s

clusters:
  - name: ext_proc
    type: STRICT_DNS
    typed_extension_protocol_options:
      envoy.extensions.upstreams.http.v3.HttpProtocolOptions:
        "@type": type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions
        explicit_http_config:
          http2_protocol_options: {}
    load_assignment:
      cluster_name: ext_proc
      endpoints:
        - lb_endpoints:
            - endpoint:
                address:
                  socket_address:
                    address: 127.0.0.1
                    port_value: 9001
```

## Testing

Потыкать сам mac-authserver:

```bash
# Check health
grpcurl -plaintext localhost:9001 grpc.health.v1.Health/Check

# List services
grpcurl -plaintext localhost:9001 list

# Auth
grpcurl -plaintext localhost:9001 envoy.service.auth.v3.Authorization/Check -d '{}'
```

Потыкать через envoy:

```bash
curl localhost:8080
```

## Architecture Benefits

- **Testability**: Each layer can be tested independently
- **Maintainability**: Clear separation of concerns
- **Extensibility**: Easy to add new authorization strategies
- **Flexibility**: Swap implementations without changing business logic
- **Clean Dependencies**: Dependencies point inward (domain has no external dependencies)