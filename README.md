# Reverse proxy MAC

Обратный прокси-сервер с поддержкой мандатного управления доступом. Реализуется в рамках проекта Астра Стипендии 2026

## Использование

У вас должен быть развернут контроллер домена ALD Pro или FreeIPA и быть доступ к серверу контроллера домена.

### Пререквизиты

1. Создать сервис в контроллере домена
    ```bash
    ipa service-add HTTP/mac-authserver.ald.company.lan
    ```
    если возникает ошибка из-за отсутствия хоста, добавить хост командой
    ```bash
    ipa host-add mac-authserver.ald.company.lan --force
    ```
    если ошибка все еще остается, попробовать создать сервис с флагом `--force`
    ```bash
    ipa service-add HTTP/mac-authserver.ald.company.lan --force
    ```

2. Выписать Kerberos ключ для сервиса

    ```bash
    ipa-getkeytab -s dc-1.ald.company.lan -p HTTP/mac-authserver.ald.company.lan -k /tmp/mac-authserver.keytab
    ```

3. Файл ключа скопировать в корень репозитория

### Локальный запуск

У вас должны быть установлены
- Docker
- docker compose
- make


1. Скопировать или переименовать `config.example.json` в `config.json` и отредактировать
2. 
    ```bash
    make docker-build
    ```

3.
    ```bash
    make docker-up
    ```

### Проверка

#### Проверить mac-authserver напрямую через `grpcurl`:
```bash
# List services
grpcurl -plaintext localhost:9001 list

# Check health
grpcurl -plaintext localhost:9001 grpc.health.v1.Health/Check
```

#### Проверить mac-authserver через `curl`:

1. В файле `/etc/hosts` указать:
    ```
    127.0.0.1       localhost mac-authserver.ald.company.lan
    ```
2. Установить необходимые пакеты для Kerberos 5
3. В файле `/etc/krb5.conf` указать
    ```conf
    [libdefaults]
        default_realm = ALD.COMPANY.LAN
        dns_lookup_realm = true
        dns_lookup_kdc = true
        ticket_lifetime = 24h
        renew_lifetime = 7d
        forwardable = true

    [realms]
        ALD.COMPANY.LAN = {
            kdc = dc-1.ald.company.lan
            admin_server = dc-1.ald.company.lan
        }

    [domain_realm]
        .ald.company.lan = ALD.COMPANY.LAN
        ald.company.lan = ALD.COMPANY.LAN

    ```
4. В терминале выполнить
    ```bash
    curl http://mac-authserver.ald.company.lan:8080
    ```

#### Проверка в браузере
TODO: описать проверку в браузере

## Runbooks

- [Сброс пароля администратора контроллера домена](./docs/runbooks/dc-reset-password.md)
- [Развертывание контроллера домена ALD Pro 3.0.0](https://www.aldpro.ru/professional/ALD_Pro_Module_02/ALD_Pro_deployment.html#aldpro-dc-packages-install)
