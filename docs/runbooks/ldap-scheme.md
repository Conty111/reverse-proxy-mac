# Расширение схемы LDAP

## Узлы

### Схема атрибутов (`aldHostContext`)

| OID | Имя | Тип | Описание |
|-----|-----|-----|----------|
| `1.3.6.1.4.1.32702.1.1.2.1` | `x-ald-host-mac` | attributeType | Минимально и максимально разрешенные классификационные метки узла, SINGLE-VALUE string |
| `1.3.6.1.4.1.32702.1.1.2.2` | `x-ald-host-mic-level` | attributeType | Максимально разрешенный уровень (категории) целостности узла (по умолчанию 0x0), SINGLE-VALUE string |
| `1.3.6.1.4.1.32702.2.2` | `aldHostContext` | objectClass | AUXILIARY-класс; MUST `x-ald-host-mac`, `x-ald-host-mic-level` |

### Установка схемы

Чтобы добавить узлам атрибуты мандатного управления доступом:

1. Файл [74x-ald-host-mac.ldif](../../74x-ald-host-mac.ldif) вместе с его содержимым создайте на сервере со службой каталога по пути `/etc/dirsrv/slapd-ALD-COMPANY-LAN/schema/74x-ald-host-mac.ldif` (путь может отличаться в зависимости от realm вашего домена)
2. Перезапустите службу каталогов:

    ```bash
    systemctl restart dirsrv@ALD-COMPANY-LAN.service
    ```

### Назначение атрибутов

Назначить созданные ранее атрибуты узла можно следующими командами (заменив `${TARGET_HOST}` на FQDN узла в домене):

```bash
ipa host-mod ${TARGET_HOST} \
  --addattr=objectClass=aldHostContext
ipa host-mod ${TARGET_HOST} \
  --addattr=x-ald-host-mac="2:0x1:3:0xFF"
```

Формат атрибутов аналогичен формату атрибутов пользователей:

  `x-ald-user-mac` - `x-ald-host-mac`
  ```
  confidentiality-min:categories-min:confidentiality-max:categories-max
  ```

  `x-ald-user-mic-level` - `x-ald-host-mic-level`

### Выдача прав

Для работы с созданными ранее атрибутами требуется выдать разрешения. Например, выдать разрешение на чтение, поиск и сравнение атрибутов для всех можно так:

```bash
ipa permission-add "Read custom host security context" \
  --type=host \
  --right={read,search,compare} \
  --attrs={x-ald-host-mac,x-ald-host-mic-level} \
  --bindtype=all
```

## HTTP URI правила

### Концепция

URI-based MAC (по аналогии с [URI-based HBAC](https://www.freeipa.org/page/V4/URI-based_HBAC)) — механизм мандатного управления доступом на уровне URI-пути.

**Ключевые отличия от ролевой модели:**

- Правило несёт **MAC-метку** (`x-ald-uri-mac`) и **категории целостности** (`x-ald-uri-mic-level`) , а не просто разрешение.
- Проверка выполняется путём сравнения меток пользователя с метками правила для данного URI-пути.

### Схема атрибутов (`aldURIMACRule`)

Структурный класс `aldURIMACRule` хранится как самостоятельная запись в дереве каталога и связывается с HTTP-службами через атрибут `x-ald-uri-service-ref`.

| OID | Имя | Тип | Описание |
|-----|-----|-----|----------|
| `1.3.6.1.4.1.32702.1.1.3.1` | `x-ald-uri-mac` | attributeType | Комплексная MAC-метка URI-ресурса, SINGLE-VALUE string, **обязательный** |
| `1.3.6.1.4.1.32702.1.1.3.2` | `x-ald-uri-mic-level` | attributeType | Максимально разрешенный уровень (категории) целостности URI (по умолчанию 0x0), SINGLE-VALUE, опциональный |
| `1.3.6.1.4.1.32702.1.1.3.3` | `x-ald-uri-match-type` | attributeType | Тип сопоставления пути: `exact` (по умолчанию), `prefix`, `regex`, SINGLE-VALUE, опциональный |
| `1.3.6.1.4.1.32702.1.1.3.4` | `x-ald-uri-description` | attributeType | Текстовое описание ресурса, SINGLE-VALUE string, опциональный |
| `1.3.6.1.4.1.32702.1.1.3.5` | `x-ald-uri-path` | attributeType | URI-путь (точный, префикс или regex-паттерн), SINGLE-VALUE string, **обязательный** |
| `1.3.6.1.4.1.32702.1.1.3.6` | `x-ald-uri-service-ref` | attributeType | DN службы HTTP, к которой привязано правило, MULTI-VALUE, опциональный |
| `1.3.6.1.4.1.32702.2.4` | `aldURIMACRule` | objectClass | STRUCTURAL-класс; MUST `cn`, `x-ald-uri-mac`, `x-ald-uri-path`; MAY остальные |

### Типы сопоставления URI-пути (`x-ald-uri-match-type`)

| Значение | Описание | Пример правила | Совпадает с |
|----------|----------|----------------|-------------|
| `exact` | Точное совпадение (по умолчанию) | `/api/secret` | только `/api/secret` |
| `prefix` | Путь запроса начинается с указанного префикса | `/api/v1` | `/api/v1`, `/api/v1/`, `/api/v1/users` |
| `regex` | Путь запроса соответствует регулярному выражению (RE2) | `/api/v[0-9]+/.*` | `/api/v1/users`, `/api/v2/items` |

При проверке доступа доступ проверяется по каждому соответствующему правилу.

### Установка схемы

1. Файл [74x-ald-uri-mac.ldif](../../74x-ald-uri-mac.ldif) вместе с его содержимым создайте на сервере со службой каталога по пути `/etc/dirsrv/slapd-ALD-COMPANY-LAN/schema/74x-ald-uri-mac.ldif`
2. Перезапустите службу каталогов:

    ```bash
    systemctl restart dirsrv@ALD-COMPANY-LAN.service
    ```

3. Создайте временный файл с содержимым файла [74x-ald-uri-references.ldif](../../74x-ald-uri-references.ldif) (например, в `/tmp/74x-ald-uri-references.ldif`)
4. Модифицируйте реферальные ссылки для атрибутов
    
    С вводом пароля администратора:
    ```bash
    ldapmodify -x -D "cn=Directory Manager" -W -f /tmp/74x-ald-uri-references.ldif
    ```
    Или с GSSAPI (предварительно нужно будет получить Kerberos билет):
    ```bash
    ldapmodify -Y GSSAPI -f /tmp/74x-ald-uri-references.ldif
    ```

### Создание URI MAC-правил

**Точное совпадение** — доступ к `/api/secret` только для уровня 2+:

```bash
ldapadd -Y GSSAPI <<EOF
dn: cn=rule-api-secret,cn=accounts,dc=ald,dc=company,dc=lan
objectClass: top
objectClass: aldURIMACRule
cn: rule-api-secret
x-ald-uri-mac: 2:0x1:3:0xFF
x-ald-uri-path: /api/secret
x-ald-uri-service-ref: krbprincipalname=HTTP/app.ald.company.lan@ALD.COMPANY.LAN,cn=services,cn=accounts,dc=ald,dc=company,dc=lan
x-ald-uri-description: Доступ к секретному API только для уровня 2+
EOF
```

**Префиксное совпадение** — весь административный раздел `/api/admin/` для уровня 3, привязан к нескольким службам:

```bash
ldapadd -Y GSSAPI <<EOF
dn: cn=rule-api-admin,cn=accounts,dc=ald,dc=company,dc=lan
objectClass: top
objectClass: aldURIMACRule
cn: rule-api-admin
x-ald-uri-mac: 3:0xFF:3:0xFF
x-ald-uri-path: /api/admin
x-ald-uri-match-type: prefix
x-ald-uri-service-ref: krbprincipalname=HTTP/app.ald.company.lan@ALD.COMPANY.LAN,cn=services,cn=accounts,dc=ald,dc=company,dc=lan
x-ald-uri-service-ref: krbprincipalname=HTTP/app2.ald.company.lan@ALD.COMPANY.LAN,cn=services,cn=accounts,dc=ald,dc=company,dc=lan
x-ald-uri-description: Административный API — уровень 3, все категории
EOF
```

**Regex-совпадение** — все версионированные API-эндпоинты `/api/v<N>/`:

```bash
ldapadd -Y GSSAPI <<EOF
dn: cn=rule-api-versioned,cn=accounts,dc=ald,dc=company,dc=lan
objectClass: top
objectClass: aldURIMACRule
cn: rule-api-versioned
x-ald-uri-mac: 2:0x3:3:0xFF
x-ald-uri-path: /api/v[0-9]+(/.*)?
x-ald-uri-match-type: regex
x-ald-uri-service-ref: krbprincipalname=HTTP/app.ald.company.lan@ALD.COMPANY.LAN,cn=services,cn=accounts,dc=ald,dc=company,dc=lan
x-ald-uri-description: Версионированные API-эндпоинты
EOF
```

### Выдача прав

```bash
ipa permission-add "Read URI MAC rules" \
  --type=service \
  --right={read,search,compare} \
  --attrs={cn,x-ald-uri-mac,x-ald-uri-mic-level,x-ald-uri-path,x-ald-uri-match-type,x-ald-uri-service-ref,x-ald-uri-description} \
  --bindtype=all
```
