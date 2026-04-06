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

---

## Prometheus Metrics

Эндпоинт `/metrics` отдаёт метрики через [`promhttp.Handler()`](../src/presentation/server/http_server.go:71). Помимо стандартных метрик Go-рантайма и процесса, регистрируются следующие прикладные метрики.

### gRPC Server Metrics

Метрики собираются библиотекой [`go-grpc-prometheus`](https://github.com/grpc-ecosystem/go-grpc-prometheus) через interceptors, подключённые в [`grpc_server.go`](../src/presentation/server/grpc_server.go).

| Метрика | Тип | Labels | Описание |
|---|---|---|---|
| `grpc_server_started_total` | Counter | `grpc_type`, `grpc_service`, `grpc_method` | Количество начатых RPC |
| `grpc_server_handled_total` | Counter | `grpc_type`, `grpc_service`, `grpc_method`, `grpc_code` | Количество завершённых RPC (с кодом ответа) |
| `grpc_server_handling_seconds` | Histogram | `grpc_type`, `grpc_service`, `grpc_method` | Latency обработки RPC (секунды) |
| `grpc_server_msg_received_total` | Counter | `grpc_type`, `grpc_service`, `grpc_method` | Количество полученных stream-сообщений |
| `grpc_server_msg_sent_total` | Counter | `grpc_type`, `grpc_service`, `grpc_method` | Количество отправленных stream-сообщений |

> **Grafana Dashboard**: импортируйте [gRPC Go dashboard (ID 14765)](https://grafana.com/grafana/dashboards/14765-grpc-go/) — он полностью совместим с этими метриками.

### LDAP Metrics

Метрики определены в [`metrics.go`](../src/infrastructure/ldap/metrics.go) и инструментированы в [`client.go`](../src/infrastructure/ldap/client.go) и [`search.go`](../src/infrastructure/ldap/search.go).

| Метрика | Тип | Labels | Описание |
|---|---|---|---|
| `mac_authserver_ldap_connection_up` | Gauge | — | Состояние LDAP-соединения (1 = активно, 0 = разорвано) |
| `mac_authserver_ldap_connections_total` | Counter | `status` | Количество попыток подключения к LDAP |
| `mac_authserver_ldap_reconnects_total` | Counter | `status` | Количество попыток переподключения к LDAP |
| `mac_authserver_ldap_search_total` | Counter | `status` | Количество LDAP-поисков |
| `mac_authserver_ldap_search_duration_seconds` | Histogram | — | Длительность LDAP-поисков (секунды) |

Label `status` принимает значения `"success"` или `"error"`.

---

## Grafana: примеры PromQL-запросов для LDAP-метрик

### Состояние соединения

```promql
mac_authserver_ldap_connection_up
```

Используйте панель **Stat** или **Gauge** с порогами: `1 = green`, `0 = red`.

### RPS LDAP-поисков

```promql
rate(mac_authserver_ldap_search_total[5m])
```

Для разделения по статусу:

```promql
sum by (status) (rate(mac_authserver_ldap_search_total[5m]))
```

### Средняя latency LDAP-поисков

```promql
rate(mac_authserver_ldap_search_duration_seconds_sum[5m])
  /
rate(mac_authserver_ldap_search_duration_seconds_count[5m])
```

### p50 / p95 / p99 latency LDAP-поисков

```promql
histogram_quantile(0.50, rate(mac_authserver_ldap_search_duration_seconds_bucket[5m]))
histogram_quantile(0.95, rate(mac_authserver_ldap_search_duration_seconds_bucket[5m]))
histogram_quantile(0.99, rate(mac_authserver_ldap_search_duration_seconds_bucket[5m]))
```

### Частота ошибок LDAP-поисков (error rate)

```promql
rate(mac_authserver_ldap_search_total{status="error"}[5m])
  /
rate(mac_authserver_ldap_search_total[5m])
```

### Частота переподключений

```promql
rate(mac_authserver_ldap_reconnects_total[5m])
```
