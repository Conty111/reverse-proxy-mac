# Metrics

HTTP-сервер запускается на порту `http_port` (по умолчанию `8080`, см. [configuration.md](./configuration.md)).

## HTTP Endpoints

| Endpoint | Описание |
|---|---|
| `/health` | Статус всех зарегистрированных компонентов (JSON) |
| `/health/live` | Kubernetes liveness probe — `200` если процесс запущен |
| `/health/ready` | Kubernetes readiness probe — `200` если все компоненты здоровы |
| `/metrics` | Метрики в формате Prometheus |

### Health

`/health` и `/health/ready` опрашивают зарегистрированные компоненты:

| Компонент | Источник | Условие "healthy" |
|---|---|---|
| `grpc` | [`GRPCServer.IsRunning()`](../src/presentation/server/grpc_server.go) | gRPC-сервер запущен |
| `ldap` | [`ldap.Client.IsConnected()`](../src/infrastructure/ldap/client.go) | LDAP-соединение активно |

Пример ответа `/health`:

```json
{
  "status": "healthy",
  "components": {
    "grpc": "healthy",
    "ldap": "healthy"
  }
}
```

При наличии нездорового компонента возвращается HTTP `503`.

### Prometheus Metrics

Эндпоинт `/metrics` отдаёт стандартные метрики Go-рантайма и процесса через [`promhttp.Handler()`](../src/presentation/server/http_server.go:73) (библиотека `prometheus/client_golang`). Кастомные метрики приложения не зарегистрированы.
