# Build stage
FROM golang:1.26.0-alpine3.23 AS builder

# Install build dependencies
RUN apk add --no-cache git make

# Set working directory
WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY src/ ./src/

# Build the application
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o authserver ./src/cmd/authserver

# Runtime stage
FROM alpine:latest

# Install runtime dependencies
RUN apk --no-cache add ca-certificates netcat-openbsd

# Create app directory
WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/authserver .

# Expose gRPC port
EXPOSE 9001

# Run the application
CMD ["./authserver"]
