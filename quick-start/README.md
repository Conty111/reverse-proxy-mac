## Quick start

Простой способ попробовать запустить Envoy с кастомным плагином, написанным на Go

Requirements:

- Golang
- docker-compose

```bash
go mod tidy
```
```bash
env GOOS=wasip1 GOARCH=wasm go build -buildmode=c-shared -o my-plugin.wasm main.go
```
```bash
docker-compose -f demo-compose.yaml up
```

### Trying

```bash
curl localhost:10000
```