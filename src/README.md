# Reverse Proxy MAC - Mandatory Access Control Proxy

Обратный прокси-сервер с поддержкой мандатного управления доступом (MAC) для интеграции с Envoy Proxy.

## Архитектура

Проект реализует external authorization service для Envoy Proxy, который:

1. **HTTP трафик**: Проверяет аутентификацию (Kerberos/OAuth2/OIDC), извлекает пользователя, получает MAC-метку из LDAP
2. **L4 трафик**: Логирует информацию о хостах, получая данные из контроллера домена

## Структура проекта

```
src/
├── cmd/                          # Точка входа приложения
│   ├── main.go                   # Главный файл
│   └── extauth.go                # gRPC сервер для Envoy ext_authz
├── config/                       # Конфигурация
│   ├── config.go                 # Структуры конфигурации
│   └── loader.go                 # Загрузчик конфигурации
├── internal/
│   ├── domain/                   # Доменная логика
│   │   ├── entities/             # Сущности
│   │   │   ├── user.go           # Пользователь с MAC-меткой
│   │   │   └── host.go           # Хост с MAC-меткой
│   │   └── ports/                # Интерфейсы
│   │       ├── auth_service.go   # Интерфейсы аутентификации
│   │       ├── ldap_service.go   # Интерфейс LDAP
│   │       └── logger.go         # Интерфейс логирования
│   └── application/              # Прикладной слой
│       ├── authentication/       # Сервис аутентификации
│       │   └── service.go
│       └── authorization/        # Сервис авторизации
│           └── service.go
└── pkg/                          # Публичные пакеты
    ├── auth/                     # Реализации аутентификации
    │   └── kerberos.go           # Kerberos аутентификация
    ├── ldap/                     # LDAP клиент
    │   └── service.go            # Работа с Active Directory
    └── logger/                   # Логирование
        └── logger.go
```

## Возможности

### Аутентификация
- ✅ **Kerberos** (по умолчанию) - проверка Kerberos tickets
- 🔄 **OAuth2** - интроспекция токенов
- 🔄 **OIDC** - проверка ID tokens

### Авторизация
- ✅ Извлечение MAC-меток пользователей из LDAP
- ✅ Проверка разрешенных меток
- ✅ Добавление заголовка `X-ALD-MAC-User` с меткой пользователя

### L4 Traffic
- ✅ Логирование информации о хостах по IP-адресу
- ✅ Извлечение MAC-меток хостов из Active Directory

## Установка

### Требования
- Go 1.21+
- Доступ к Kerberos KDC
- Доступ к LDAP/Active Directory
- Envoy Proxy

### Сборка

```bash
cd src
go mod download
go build -o reverse-proxy-mac ./cmd
```

## Конфигурация

Создайте файл `config.json` на основе [`config.example.json`](config.example.json):

```json
{
  "server": {
    "host": "0.0.0.0",
    "grpc_port": 9001
  },
  "auth": {
    "default": "kerberos",
    "kerberos": {
      "enabled": true,
      "kdc_address": "dc-1.ald.company.lan:88",
      "realm": "ALD.COMPANY.LAN",
      "service_name": "HTTP/proxy.ald.company.lan",
      "keytab_path": "/etc/krb5.keytab"
    }
  },
  "ldap": {
    "host": "dc-1.ald.company.lan",
    "port": 389,
    "base_dn": "DC=ald,DC=company,DC=lan",
    "bind_dn": "CN=proxy-service,OU=ServiceAccounts,DC=ald,DC=company,DC=lan",
    "bind_password": "password",
    "mac_label_attribute": "msDS-AssignedAuthNPolicy"
  },
  "mac": {
    "enabled": true,
    "allowed_labels": ["secret", "top-secret", "confidential", "public"],
    "header_name": "X-ALD-MAC-User"
  }
}
```

### Конфигурация Envoy

Пример конфигурации Envoy для использования external authorization:

```yaml
static_resources:
  listeners:
  - name: main
    address:
      socket_address:
        address: 0.0.0.0
        port_value: 8080
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: ingress_http
          http_filters:
          - name: envoy.filters.http.ext_authz
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
              grpc_service:
                envoy_grpc:
                  cluster_name: ext_authz
                timeout: 5s
          - name: envoy.filters.http.router
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router

  clusters:
  - name: ext_authz
    type: STRICT_DNS
    connect_timeout: 1s
    http2_protocol_options: {}
    load_assignment:
      cluster_name: ext_authz
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                address: reverse-proxy-mac
                port_value: 9001
```

## Запуск

```bash
# С конфигурацией по умолчанию
./reverse-proxy-mac

# С указанием пути к конфигурации
CONFIG_PATH=/path/to/config.json ./reverse-proxy-mac
```

## Использование

### HTTP запросы

Клиент отправляет запрос с Kerberos ticket:

```bash
curl -H "Authorization: Negotiate <base64-encoded-ticket>" \
     http://proxy.example.com/api/resource
```

Прокси:
1. Проверяет Kerberos ticket
2. Извлекает username и realm
3. Получает MAC-метку из LDAP
4. Проверяет, что метка в списке разрешенных
5. Добавляет заголовки:
   - `X-Authenticated-User: user@REALM`
   - `X-Username: user`
   - `X-Realm: REALM`
   - `X-ALD-MAC-User: secret`
6. Пропускает запрос к backend

### L4 трафик

Для L4 трафика прокси логирует информацию о хостах:

```
[INFO] L4 traffic detected | src_ip=192.168.1.100 dst_ip=192.168.1.200
[INFO] Source host info | ip=192.168.1.100 hostname=client.example.com mac_label=confidential
[INFO] Destination host info | ip=192.168.1.200 hostname=server.example.com mac_label=secret
```

## Разработка

### Архитектурные принципы

Проект следует принципам Clean Architecture:

- **Domain Layer**: Бизнес-логика и интерфейсы (ports)
- **Application Layer**: Use cases и оркестрация
- **Infrastructure Layer**: Реализации (adapters) - LDAP, Kerberos, gRPC

### Добавление нового метода аутентификации

1. Реализуйте интерфейс `ports.AuthService` в `pkg/auth/`
2. Добавьте конфигурацию в `config/config.go`
3. Зарегистрируйте в `cmd/main.go`

## Логирование

Уровни логирования:
- `debug`: Детальная информация для отладки
- `info`: Общая информация о работе
- `warn`: Предупреждения
- `error`: Ошибки
- `fatal`: Критические ошибки с остановкой

## Безопасность

- Keytab файл должен быть защищен (chmod 600)
- LDAP пароли хранятся в конфигурации - используйте secrets management
- Рекомендуется использовать TLS для LDAP соединений
- gRPC соединение с Envoy должно быть защищено в production

## Лицензия

Proprietary - ALD Company

## Контакты

Для вопросов и поддержки: support@ald.company.lan
