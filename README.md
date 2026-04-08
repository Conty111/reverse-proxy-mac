# Reverse proxy MAC

Обратный прокси-сервер с поддержкой мандатного управления доступом. Реализуется в рамках проекта Астра Стипендии 2026

## Архитектура

- [Обзор дизайна системы](./docs/design.md)
- [Модель управления доступом](./docs/access.md)

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
2. Выдать права на чтение пользовательских атрибутов

    ```bash
    ipa role-add "User Attribute Reader" --desc="Can read user attributes"
    ipa role-add-privilege "User Attribute Reader" --privileges="User Administrators"
    ipa role-add-member "User Attribute Reader" --services=HTTP/mac-authserver.ald.company.lan@ALD.COMPANY.LAN
    ```

3. Выписать Kerberos ключ для сервиса

    ```bash
    ipa-getkeytab -s dc-1.ald.company.lan -p HTTP/mac-authserver.ald.company.lan -k /tmp/mac-authserver.keytab
    ```

4. Файл ключа скопировать в корень репозитория
5. [Расширить схему LDAP](./docs/runbooks/ldap-scheme.md)

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

Необходим браузер, поддерживающий Kerberos авторизацию.

1. Настроить браузер для Kerberos авторизации в домене
2. Получить Kerberos тикет (можно в терминале командой `kinit <user>@<REALM>`)
3. Перейти по адресу <http://mac-authserver.ald.company.lan:8080>

Проверить работоспособность Kerberos авторизации в браузере можно попробовав войти в систему FreeIPA в Web UI ***не вводя имя пользователя и пароль*** (по адресу `https://<your.domain.controller.address/ipa/ui/`)


## Пошаговые инструкции

- [Расширение схемы LDAP в командной строке](./docs/runbooks/ldap-scheme.md)
- [Обеспечение TLS соединения с LDAP](./docs/runbooks/tls.md)
- [Сброс пароля администратора контроллера домена](./docs/runbooks/dc-reset-password.md)
- [Развертывание контроллера домена ALD Pro 3.0.0](https://www.aldpro.ru/professional/ALD_Pro_Module_02/ALD_Pro_deployment.html#aldpro-dc-packages-install)
- [Развертывание контроллера домена FreeIPA на Astra Linux](https://wiki.astralinux.ru/pages/viewpage.action?pageId=27362143)
- [Ввод Astra Linux в домен FreeIPA](https://wiki.astralinux.ru/pages/viewpage.action?pageId=60359750)
- [Чтение пользовательских атрибутов (настройка прав)](https://wiki.astralinux.ru/pages/viewpage.action?pageId=153488486)