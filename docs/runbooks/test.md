# Сценарии ручного тестирования

Данный документ описывает сценарии ручного тестирования мандатного управления доступом (MAC) для сервиса ReverseProxyMAC.

## Содержание

- [Предварительные требования](#предварительные-требования)
- [Переменные окружения](#переменные-окружения)
- [Сценарий 1: Создание пользователя с метками](#сценарий-1-создание-пользователя-с-метками)
- [Сценарий 2: Создание хоста с метками](#сценарий-2-создание-хоста-с-метками)
- [Сценарий 3: Создание URI-правил с метками](#сценарий-3-создание-uri-правил-с-метками)
- [Сценарий 4: Проверка доступа на уровне хоста](#сценарий-4-проверка-доступа-на-уровне-хоста)
- [Сценарий 5: Проверка доступа на уровне URI](#сценарий-5-проверка-доступа-на-уровне-uri)
- [Сценарий 6: Проверка запрета доступа](#сценарий-6-проверка-запрета-доступа)
- [Команды ldapsearch для поиска сущностей](#команды-ldapsearch-для-поиска-сущностей)
- [Очистка тестовых данных](#очистка-тестовых-данных)

---

## Предварительные требования

1. Установленная и настроенная служба каталогов (FreeIPA/ALD Pro)
2. Расширенная схема LDAP (см. [ldap-scheme.md](./ldap-scheme.md))
3. Настроенный Kerberos-клиент
4. Доступ к `ipa` CLI и `ldapsearch`/`ldapadd`/`ldapmodify`
5. Запущенный сервис авторизации ReverseProxyMAC

## Переменные окружения

Перед выполнением тестов установите переменные окружения:

```bash
# Домен
export DOMAIN="ald.company.lan"
export BASE_DN="dc=ald,dc=company,dc=lan"

# Тестовые пользователи
export TEST_USER_LOW="testuser-low"
export TEST_USER_MID="testuser-mid"
export TEST_USER_HIGH="testuser-high"

# Тестовые хосты
export TEST_HOST_LOW="app-low.${DOMAIN}"
export TEST_HOST_MID="app-mid.${DOMAIN}"
export TEST_HOST_HIGH="app-high.${DOMAIN}"

# Сервис авторизации
export AUTH_SERVER="http://localhost:8080"
```

---

## Сценарий 1: Создание пользователя с метками

### 1.1 Создание пользователей с разными уровнями конфиденциальности

**Формат метки:** `confidentiality-min:categories-min:confidentiality-max:categories-max`

#### Пользователь с низким уровнем (уровень 0-1)

```bash
# Создание пользователя
ipa user-add ${TEST_USER_LOW} \
  --first="Test" \
  --last="UserLow" \
  --password

# Назначение MAC-метки: уровень 0-1, без категорий
ipa user-mod ${TEST_USER_LOW} \
  --addattr=x-ald-user-mac="0:0x0:1:0x0"

# Назначение уровня целостности (опционально)
ipa user-mod ${TEST_USER_LOW} \
  --addattr=x-ald-user-mic-level="0x0"
```

#### Пользователь со средним уровнем (уровень 1-2)

```bash
# Создание пользователя
ipa user-add ${TEST_USER_MID} \
  --first="Test" \
  --last="UserMid" \
  --password

# Назначение MAC-метки: уровень 1-2, категории 0x1 и 0x2
ipa user-mod ${TEST_USER_MID} \
  --addattr=x-ald-user-mac="1:0x3:2:0x3"

# Назначение уровня целостности
ipa user-mod ${TEST_USER_MID} \
  --addattr=x-ald-user-mic-level="0x1"
```

#### Пользователь с высоким уровнем (уровень 2-3)

```bash
# Создание пользователя
ipa user-add ${TEST_USER_HIGH} \
  --first="Test" \
  --last="UserHigh" \
  --password

# Назначение MAC-метки: уровень 2-3, все категории
ipa user-mod ${TEST_USER_HIGH} \
  --addattr=x-ald-user-mac="2:0xFF:3:0xFF"

# Назначение уровня целостности
ipa user-mod ${TEST_USER_HIGH} \
  --addattr=x-ald-user-mic-level="0x3"
```

### 1.2 Проверка созданных пользователей

```bash
# Проверка атрибутов пользователя
ipa user-show ${TEST_USER_LOW} --all --raw
ipa user-show ${TEST_USER_MID} --all --raw
ipa user-show ${TEST_USER_HIGH} --all --raw
```

**Ожидаемый результат:** Атрибуты `x-ald-user-mac` и `x-ald-user-mic-level` отображаются в выводе.

---

## Сценарий 2: Создание хоста с метками

### 2.1 Создание хостов с разными уровнями конфиденциальности

#### Хост с низким уровнем (уровень 0-1)

```bash
# Создание хоста (если не существует)
ipa host-add ${TEST_HOST_LOW} --force

# Добавление auxiliary-класса для MAC-атрибутов
ipa host-mod ${TEST_HOST_LOW} \
  --addattr=objectClass=aldHostContext

# Назначение MAC-метки хосту
ipa host-mod ${TEST_HOST_LOW} \
  --addattr=x-ald-host-mac="0:0x0:1:0x0"

# Назначение уровня целостности
ipa host-mod ${TEST_HOST_LOW} \
  --addattr=x-ald-host-mic-level="0x0"
```

#### Хост со средним уровнем (уровень 1-2)

```bash
ipa host-add ${TEST_HOST_MID} --force

ipa host-mod ${TEST_HOST_MID} \
  --addattr=objectClass=aldHostContext

ipa host-mod ${TEST_HOST_MID} \
  --addattr=x-ald-host-mac="1:0x3:2:0x3"

ipa host-mod ${TEST_HOST_MID} \
  --addattr=x-ald-host-mic-level="0x1"
```

#### Хост с высоким уровнем (уровень 2-3)

```bash
ipa host-add ${TEST_HOST_HIGH} --force

ipa host-mod ${TEST_HOST_HIGH} \
  --addattr=objectClass=aldHostContext

ipa host-mod ${TEST_HOST_HIGH} \
  --addattr=x-ald-host-mac="2:0xFF:3:0xFF"

ipa host-mod ${TEST_HOST_HIGH} \
  --addattr=x-ald-host-mic-level="0x3"
```

### 2.2 Проверка созданных хостов

```bash
ipa host-show ${TEST_HOST_LOW} --all --raw
ipa host-show ${TEST_HOST_MID} --all --raw
ipa host-show ${TEST_HOST_HIGH} --all --raw
```

**Ожидаемый результат:** Атрибуты `x-ald-host-mac` и `x-ald-host-mic-level` отображаются в выводе.

---

## Сценарий 3: Создание URI-правил с метками

### 3.0 Создание контейнера для URI MAC-правил (однократно)

Перед созданием правил необходимо создать контейнер в LDAP:

```bash
ldapadd -Y GSSAPI <<EOF
dn: cn=uri-mac-rules,cn=accounts,${BASE_DN}
objectClass: top
objectClass: nsContainer
cn: uri-mac-rules
EOF
```

### 3.1 Создание URI-правил с разными типами сопоставления

> **Примечание:** Атрибут `cn` содержит уникальное имя правила, а URI-путь хранится в атрибуте `x-ald-uri-path`.

#### Правило с точным совпадением (exact)

```bash
ldapadd -Y GSSAPI <<EOF
dn: cn=rule-api-secret,cn=uri-mac-rules,cn=accounts,${BASE_DN}
objectClass: top
objectClass: aldURIMACRule
cn: rule-api-secret
x-ald-uri-path: /api/secret
x-ald-uri-mac: 2:0x1:3:0xFF
x-ald-uri-service-ref: krbprincipalname=HTTP/${TEST_HOST_MID}@${REALM},cn=services,cn=accounts,${BASE_DN}
x-ald-uri-description: Тестовое правило - точное совпадение /api/secret
EOF
```

#### Правило с префиксным совпадением (prefix), привязанное к нескольким службам

```bash
ldapadd -Y GSSAPI <<EOF
dn: cn=rule-api-admin,cn=uri-mac-rules,cn=accounts,${BASE_DN}
objectClass: top
objectClass: aldURIMACRule
cn: rule-api-admin
x-ald-uri-path: /api/admin
x-ald-uri-mac: 1:0x0:2:0x3
x-ald-uri-match-type: prefix
x-ald-uri-service-ref: krbprincipalname=HTTP/${TEST_HOST_MID}@${REALM},cn=services,cn=accounts,${BASE_DN}
x-ald-uri-service-ref: krbprincipalname=HTTP/${TEST_HOST_HIGH}@${REALM},cn=services,cn=accounts,${BASE_DN}
x-ald-uri-description: Тестовое правило - префикс /api/admin/*
EOF
```

#### Правило с regex-совпадением

```bash
ldapadd -Y GSSAPI <<EOF
dn: cn=rule-api-users-regex,cn=uri-mac-rules,cn=accounts,${BASE_DN}
objectClass: top
objectClass: aldURIMACRule
cn: rule-api-users-regex
x-ald-uri-path: /api/v[0-9]+/users/[0-9]+
x-ald-uri-mac: 1:0x1:2:0x1
x-ald-uri-match-type: regex
x-ald-uri-service-ref: krbprincipalname=HTTP/${TEST_HOST_MID}@${REALM},cn=services,cn=accounts,${BASE_DN}
x-ald-uri-description: Тестовое правило - regex для /api/v*/users/*
EOF
```

#### Правило для нескольких служб (reports)

```bash
ldapadd -Y GSSAPI <<EOF
dn: cn=rule-api-reports,cn=uri-mac-rules,cn=accounts,${BASE_DN}
objectClass: top
objectClass: aldURIMACRule
cn: rule-api-reports
x-ald-uri-path: /api/reports
x-ald-uri-mac: 2:0x0:3:0xFF
x-ald-uri-match-type: prefix
x-ald-uri-service-ref: krbprincipalname=HTTP/${TEST_HOST_MID}@${REALM},cn=services,cn=accounts,${BASE_DN}
x-ald-uri-service-ref: krbprincipalname=HTTP/${TEST_HOST_HIGH}@${REALM},cn=services,cn=accounts,${BASE_DN}
x-ald-uri-description: Тестовое правило для нескольких служб
EOF
```

### 3.2 Синхронизация правил в сервисе авторизации

После создания правил необходимо синхронизировать кэш:

```bash
curl -X POST ${AUTH_SERVER}/sync/uri-rules
```

**Ожидаемый результат:** HTTP 200 OK

---

## Сценарий 4: Проверка доступа на уровне хоста

### 4.1 Тест: Пользователь с низким уровнем → Хост с низким уровнем

**Ожидание:** Доступ РАЗРЕШЁН (диапазоны пересекаются: 0-1 ∩ 0-1)

```bash
# Получение Kerberos-тикета
kinit ${TEST_USER_LOW}

# Тестовый запрос через Envoy (GET - чтение)
curl -v --negotiate -u : \
  -H "Host: ${TEST_HOST_LOW}" \
  "http://localhost:8080/api/test"
```

**Ожидаемый результат:** HTTP 200 OK

### 4.2 Тест: Пользователь с низким уровнем → Хост с высоким уровнем

**Ожидание:** Доступ ЗАПРЕЩЁН (диапазоны не пересекаются: 0-1 ∩ 2-3 = ∅)

```bash
kinit ${TEST_USER_LOW}

curl -v --negotiate -u : \
  -H "Host: ${TEST_HOST_HIGH}" \
  "http://localhost:8080/api/test"
```

**Ожидаемый результат:** HTTP 403 Forbidden

### 4.3 Тест: Пользователь с высоким уровнем → Хост со средним уровнем

**Ожидание:** Доступ РАЗРЕШЁН для чтения (диапазоны пересекаются: 2-3 ∩ 1-2 = 2)

```bash
kinit ${TEST_USER_HIGH}

# GET-запрос (чтение)
curl -v --negotiate -u : \
  -H "Host: ${TEST_HOST_MID}" \
  "http://localhost:8080/api/test"
```

**Ожидаемый результат:** HTTP 200 OK

### 4.4 Тест: Проверка категорий конфиденциальности

**Ожидание:** Доступ ЗАПРЕЩЁН, если категории пользователя не включают категории хоста

```bash
# Создание пользователя с категорией 0x1
ipa user-add testuser-cat1 --first="Test" --last="Cat1" --password
ipa user-mod testuser-cat1 --addattr=x-ald-user-mac="1:0x1:2:0x1"

# Создание хоста с категорией 0x2
ipa host-add app-cat2.${DOMAIN} --force
ipa host-mod app-cat2.${DOMAIN} --addattr=objectClass=aldHostContext
ipa host-mod app-cat2.${DOMAIN} --addattr=x-ald-host-mac="1:0x2:2:0x2"
ipa host-mod app-cat2.${DOMAIN} --addattr=x-ald-host-mic-level="0x0"

kinit testuser-cat1

curl -v --negotiate -u : \
  -H "Host: app-cat2.${DOMAIN}" \
  "http://localhost:8080/api/test"
```

**Ожидаемый результат:** HTTP 403 Forbidden (категория 0x1 не включает 0x2)

---

## Сценарий 5: Проверка доступа на уровне URI

### 5.1 Тест: Доступ к URI с точным совпадением

**Правило:** `/api/secret` требует уровень 2-3

```bash
kinit ${TEST_USER_HIGH}

# Запрос к защищённому URI
curl -v --negotiate -u : \
  -H "Host: ${TEST_HOST_MID}" \
  "http://localhost:8080/api/secret"
```

**Ожидаемый результат:** HTTP 200 OK

```bash
kinit ${TEST_USER_LOW}

curl -v --negotiate -u : \
  -H "Host: ${TEST_HOST_MID}" \
  "http://localhost:8080/api/secret"
```

**Ожидаемый результат:** HTTP 403 Forbidden

### 5.2 Тест: Доступ к URI с префиксным совпадением

**Правило:** `/api/admin/*` требует уровень 1-2

```bash
kinit ${TEST_USER_MID}

# Запрос к /api/admin/users
curl -v --negotiate -u : \
  -H "Host: ${TEST_HOST_MID}" \
  "http://localhost:8080/api/admin/users"

# Запрос к /api/admin/settings/security
curl -v --negotiate -u : \
  -H "Host: ${TEST_HOST_MID}" \
  "http://localhost:8080/api/admin/settings/security"
```

**Ожидаемый результат:** HTTP 200 OK для обоих запросов

### 5.3 Тест: Доступ к URI с regex-совпадением

**Правило:** `/api/v[0-9]+/users/[0-9]+` требует уровень 1-2

```bash
kinit ${TEST_USER_MID}

# Запрос, соответствующий regex
curl -v --negotiate -u : \
  -H "Host: ${TEST_HOST_MID}" \
  "http://localhost:8080/api/v1/users/123"

curl -v --negotiate -u : \
  -H "Host: ${TEST_HOST_MID}" \
  "http://localhost:8080/api/v2/users/456"
```

**Ожидаемый результат:** HTTP 200 OK

```bash
# Запрос, НЕ соответствующий regex (буквы вместо цифр)
curl -v --negotiate -u : \
  -H "Host: ${TEST_HOST_MID}" \
  "http://localhost:8080/api/v1/users/abc"
```

**Ожидаемый результат:** HTTP 200 OK (правило не применяется, проверяется только хост)

### 5.4 Тест: Запись (POST/PUT/DELETE) требует точного совпадения диапазонов

**Правило:** `/api/admin/*` требует уровень 1-2

```bash
kinit ${TEST_USER_MID}

# POST-запрос (запись) - диапазоны должны совпадать
curl -v --negotiate -u : \
  -X POST \
  -H "Host: ${TEST_HOST_MID}" \
  -H "Content-Type: application/json" \
  -d '{"name": "test"}' \
  "http://localhost:10000/api/admin/users"
```

**Ожидаемый результат:** HTTP 200 OK (диапазон пользователя 1-2 совпадает с правилом 1-2)

```bash
kinit ${TEST_USER_HIGH}

# POST-запрос от пользователя с уровнем 2-3
curl -v --negotiate -u : \
  -X POST \
  -H "Host: ${TEST_HOST_MID}" \
  -H "Content-Type: application/json" \
  -d '{"name": "test"}' \
  "http://localhost:10000/api/admin/users"
```

**Ожидаемый результат:** HTTP 403 Forbidden (диапазон 2-3 не совпадает с 1-2)

---

## Сценарий 6: Проверка запрета доступа

### 6.1 Тест: Несовпадение уровней конфиденциальности

| Пользователь | Хост/URI | Операция | Ожидание |
|--------------|----------|----------|----------|
| 0-1 | 2-3 | GET | ЗАПРЕЩЕНО |
| 0-1 | 2-3 | POST | ЗАПРЕЩЕНО |
| 2-3 | 0-1 | GET | РАЗРЕШЕНО |
| 2-3 | 0-1 | POST | ЗАПРЕЩЕНО |

### 6.2 Тест: Несовпадение категорий

```bash
# Пользователь с категориями 0x1
kinit testuser-cat1

# Хост/URI с категориями 0x3 (включает 0x1 и 0x2)
curl -v --negotiate -u : \
  -H "Host: ${TEST_HOST_MID}" \
  "http://localhost:8080/api/test"
```

**Ожидаемый результат:** HTTP 403 Forbidden (категории пользователя 0x1 не включают все категории хоста 0x3)

### 6.3 Тест: Несовпадение категорий целостности

```bash
# Создание пользователя с низким уровнем целостности
ipa user-add testuser-lowint --first="Test" --last="LowInt" --password
ipa user-mod testuser-lowint --addattr=x-ald-user-mac="2:0xFF:3:0xFF"
ipa user-mod testuser-lowint --addattr=x-ald-user-mic-level="0x0"

kinit testuser-lowint

# POST-запрос к хосту с высоким уровнем целостности
curl -v --negotiate -u : \
  -X POST \
  -H "Host: ${TEST_HOST_HIGH}" \
  -H "Content-Type: application/json" \
  -d '{"data": "test"}' \
  "http://localhost:8080/api/data"
```

**Ожидаемый результат:** HTTP 403 Forbidden (целостность пользователя 0x0 не включает целостность хоста 0x3)

---

## Команды ldapsearch для поиска сущностей

### Поиск пользователей с MAC-метками

```bash
# Все пользователи с атрибутом x-ald-user-mac
ldapsearch -Y GSSAPI \
  -b "cn=users,cn=accounts,${BASE_DN}" \
  "(x-ald-user-mac=*)" \
  uid x-ald-user-mac x-ald-user-mic-level

# Пользователи с определённым уровнем конфиденциальности (начинается с "2:")
ldapsearch -Y GSSAPI \
  -b "cn=users,cn=accounts,${BASE_DN}" \
  "(x-ald-user-mac=2:*)" \
  uid x-ald-user-mac

# Конкретный пользователь
ldapsearch -Y GSSAPI \
  -b "cn=users,cn=accounts,${BASE_DN}" \
  "(uid=${TEST_USER_HIGH})" \
  uid x-ald-user-mac x-ald-user-mic-level
```

### Поиск хостов с MAC-метками

```bash
# Все хосты с классом aldHostContext
ldapsearch -Y GSSAPI \
  -b "cn=computers,cn=accounts,${BASE_DN}" \
  "(objectClass=aldHostContext)" \
  fqdn x-ald-host-mac x-ald-host-mic-level

# Хосты с определённым уровнем конфиденциальности
ldapsearch -Y GSSAPI \
  -b "cn=computers,cn=accounts,${BASE_DN}" \
  "(&(objectClass=aldHostContext)(x-ald-host-mac=2:*))" \
  fqdn x-ald-host-mac

# Конкретный хост
ldapsearch -Y GSSAPI \
  -b "cn=computers,cn=accounts,${BASE_DN}" \
  "(fqdn=${TEST_HOST_MID})" \
  fqdn x-ald-host-mac x-ald-host-mic-level
```

### Поиск URI MAC-правил

> **Примечание:** Атрибут `cn` содержит имя правила, а URI-путь хранится в атрибуте `x-ald-uri-path`.

```bash
# Все URI MAC-правила
ldapsearch -Y GSSAPI \
  -b "cn=uri-mac-rules,cn=accounts,${BASE_DN}" \
  "(objectClass=aldURIMACRule)" \
  cn x-ald-uri-path x-ald-uri-mac x-ald-uri-match-type x-ald-uri-service-ref x-ald-uri-description

# Правила для конкретной HTTP-службы
ldapsearch -Y GSSAPI \
  -b "cn=uri-mac-rules,cn=accounts,${BASE_DN}" \
  "(&(objectClass=aldURIMACRule)(x-ald-uri-service-ref=krbprincipalname=HTTP/${TEST_HOST_MID}@${REALM},cn=services,cn=accounts,${BASE_DN}))" \
  cn x-ald-uri-path x-ald-uri-mac

# Правила с определённым типом сопоставления
ldapsearch -Y GSSAPI \
  -b "cn=uri-mac-rules,cn=accounts,${BASE_DN}" \
  "(&(objectClass=aldURIMACRule)(x-ald-uri-match-type=prefix))" \
  cn x-ald-uri-path x-ald-uri-mac

# Правила с несколькими привязанными службами
ldapsearch -Y GSSAPI \
  -b "cn=uri-mac-rules,cn=accounts,${BASE_DN}" \
  "(&(objectClass=aldURIMACRule)(x-ald-uri-service-ref=*))" \
  cn x-ald-uri-path x-ald-uri-service-ref

# Поиск правила по имени
ldapsearch -Y GSSAPI \
  -b "cn=uri-mac-rules,cn=accounts,${BASE_DN}" \
  "(cn=rule-api-secret)" \
  cn x-ald-uri-path x-ald-uri-mac x-ald-uri-match-type x-ald-uri-service-ref

# Поиск правил по URI-пути (точное совпадение)
ldapsearch -Y GSSAPI \
  -b "cn=uri-mac-rules,cn=accounts,${BASE_DN}" \
  "(x-ald-uri-path=/api/secret)" \
  cn x-ald-uri-path x-ald-uri-mac x-ald-uri-match-type

# Поиск правил по URI-пути (подстрока)
ldapsearch -Y GSSAPI \
  -b "cn=uri-mac-rules,cn=accounts,${BASE_DN}" \
  "(x-ald-uri-path=*/api/*)" \
  cn x-ald-uri-path x-ald-uri-mac x-ald-uri-match-type
```

### Поиск HTTP-служб

```bash
# Все HTTP-службы в домене
ldapsearch -Y GSSAPI \
  -b "cn=services,cn=accounts,${BASE_DN}" \
  "(krbprincipalname=HTTP/*)" \
  krbprincipalname

# Конкретная HTTP-служба
ldapsearch -Y GSSAPI \
  -b "cn=services,cn=accounts,${BASE_DN}" \
  "(krbprincipalname=HTTP/${TEST_HOST_MID}@${REALM})" \
  krbprincipalname
```

### Поиск с использованием простой аутентификации

Если GSSAPI недоступен, можно использовать простую аутентификацию:

```bash
# С вводом пароля
ldapsearch -x -D "cn=Directory Manager" -W \
  -b "cn=users,cn=accounts,${BASE_DN}" \
  "(x-ald-user-mac=*)" \
  uid x-ald-user-mac

# С паролем из файла
ldapsearch -x -D "cn=Directory Manager" -y /path/to/password-file \
  -b "cn=users,cn=accounts,${BASE_DN}" \
  "(x-ald-user-mac=*)" \
  uid x-ald-user-mac
```

---

## Очистка тестовых данных

### Удаление тестовых пользователей

```bash
ipa user-del ${TEST_USER_LOW}
ipa user-del ${TEST_USER_MID}
ipa user-del ${TEST_USER_HIGH}
ipa user-del testuser-cat1
ipa user-del testuser-lowint
```

### Удаление тестовых хостов

```bash
ipa host-del ${TEST_HOST_LOW}
ipa host-del ${TEST_HOST_MID}
ipa host-del ${TEST_HOST_HIGH}
ipa host-del app-cat2.${DOMAIN}
```

### Удаление тестовых URI-правил

```bash
ldapdelete -Y GSSAPI "cn=rule-api-secret,cn=uri-mac-rules,cn=accounts,${BASE_DN}"
ldapdelete -Y GSSAPI "cn=rule-api-admin,cn=uri-mac-rules,cn=accounts,${BASE_DN}"
ldapdelete -Y GSSAPI "cn=rule-api-users-regex,cn=uri-mac-rules,cn=accounts,${BASE_DN}"
ldapdelete -Y GSSAPI "cn=rule-api-reports,cn=uri-mac-rules,cn=accounts,${BASE_DN}"
```

### Синхронизация после очистки

```bash
curl -X POST ${AUTH_SERVER}/sync/uri-rules
```

---

## Матрица тестовых сценариев

| # | Пользователь (MAC) | Хост (MAC) | URI (MAC) | Метод | Ожидание | Причина |
|---|-------------------|------------|-----------|-------|----------|---------|
| 1 | 0:0x0:1:0x0 | 0:0x0:1:0x0 | - | GET | ✅ ALLOW | Диапазоны пересекаются |
| 2 | 0:0x0:1:0x0 | 2:0xFF:3:0xFF | - | GET | ❌ DENY | Диапазоны не пересекаются |
| 3 | 2:0xFF:3:0xFF | 1:0x3:2:0x3 | - | GET | ✅ ALLOW | Диапазоны пересекаются (2) |
| 4 | 2:0xFF:3:0xFF | 1:0x3:2:0x3 | - | POST | ❌ DENY | Диапазоны не совпадают |
| 5 | 1:0x1:2:0x1 | 1:0x3:2:0x3 | - | GET | ❌ DENY | Категории не включают |
| 6 | 1:0x3:2:0x3 | 1:0x3:2:0x3 | 2:0x1:3:0xFF | GET | ❌ DENY | URI требует уровень 2+ |
| 7 | 2:0xFF:3:0xFF | 1:0x3:2:0x3 | 2:0x1:3:0xFF | GET | ✅ ALLOW | Все проверки пройдены |
| 8 | 2:0xFF:3:0xFF | 1:0x3:2:0x3 | 1:0x0:2:0x3 | POST | ❌ DENY | URI диапазон не совпадает |
