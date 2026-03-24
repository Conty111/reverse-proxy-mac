# Расширение схемы LDAP

## Добавление меток узлам

### Схема атрибутов хоста (`aldHostContext`)

| OID | Имя | Тип | Описание |
|-----|-----|-----|----------|
| `1.3.6.1.4.1.32702.1.1.2.1` | `x-ald-host-mac` | attributeType | Комплексная MAC-метка хоста, SINGLE-VALUE string |
| `1.3.6.1.4.1.32702.2.2` | `aldHostContext` | objectClass | AUXILIARY-класс; MUST `x-ald-host-mac` |

Чтобы добавить узлам атрибуты мандатного управления доступом:

1. Файл [74x-ald-host-mac.ldif](../../74x-ald-host-mac.ldif) вместе с его содержимым создайте на сервере со службой каталога по пути `/etc/dirsrv/slapd-ALD-COMPANY-LAN/schema/74x-ald-host-mac.ldif` (путь может отличаться в зависимости от realm вашего домена)
2. Перезапустите службу каталогов:

    ```bash
    systemctl restart dirsrv@ALD-COMPANY-LAN.service
    ```

Назначить созданные ранее атрибуты узла можно следующими командами (заменив `${TARGET_HOST}` на FQDN узла в домене):

```bash
ipa host-mod ${TARGET_HOST} \
  --addattr=objectClass=aldHostContext
ipa host-mod ${TARGET_HOST} \
  --addattr=x-ald-host-mac="2:0x1:0:0x0"
```

Формат атрибута аналогичен формату атрибутов пользователей `x-ald-user-mac`:

```bash
confidentiality:categories:capabilities:integrity
```

### Выдать права на чтение

Для работы с созданными ранее атрибутами требуется выдать разрешения. Например, выдать разрешение на чтение, поиск и сравнени атрибутов для всех можно так:
```bash
ipa permission-add "Read custom host security context" \
  --type=host \
  --right={read,search,compare} \
  --attrs=x-ald-host-mac \
  --bindtype=all
```

## Создание новой сущности

## Добавление меток URL-ресурсам

### Схема атрибутов URL-ресурса (`aldURLContext`)

| OID | Имя | Тип | Описание |
|-----|-----|-----|----------|
| `1.3.6.1.4.1.32702.1.1.3.1` | `x-ald-url-mac` | attributeType | Комплексная MAC-метка URL-ресурса, SINGLE-VALUE string, обязательный |
| `1.3.6.1.4.1.32702.1.1.3.2` | `x-ald-url-glob` | attributeType | Boolean: если `TRUE` — путь является glob-выражением, SINGLE-VALUE, опциональный |
| `1.3.6.1.4.1.32702.1.1.3.3` | `x-ald-url-description` | attributeType | Текстовое описание ресурса, SINGLE-VALUE string, опциональный |
| `1.3.6.1.4.1.32702.2.3` | `aldURLContext` | objectClass | AUXILIARY-класс; MUST `x-ald-url-mac`, MAY `x-ald-url-glob`, `x-ald-url-description` |


Чтобы добавить URL-ресурсам атрибуты мандатного управления доступом:

1. Файл [74x-ald-url-mac.ldif](../../74x-ald-url-mac.ldif) вместе с его содержимым создайте на сервере со службой каталога по пути `/etc/dirsrv/slapd-ALD-COMPANY-LAN/schema/74x-ald-url-mac.ldif` (путь может отличаться в зависимости от realm вашего домена)
2. Перезапустите службу каталогов:

    ```bash
    systemctl restart dirsrv@ALD-COMPANY-LAN.service
    ```

Назначить созданные ранее атрибуты URL-ресурса можно следующими командами (заменив `${TARGET_HOST}` на FQDN узла, к которому привязывается ресурс, и `${URL_CN}` на уникальное имя записи):

```bash
# Создать запись URL-ресурса и привязать её к хосту
ldapadd -Y GSSAPI <<EOF
dn: fqdn=${TARGET_HOST},cn=computers,cn=accounts,dc=ald,dc=company,dc=lan
objectClass: top
objectClass: aldURLContext
cn: ${URL_CN}
x-ald-url-mac: 2:0x1:0:0x0
x-ald-url-glob: FALSE
x-ald-url-description: Описание ресурса
EOF
```

Формат атрибута `x-ald-url-mac` аналогичен формату атрибутов пользователей `x-ald-user-mac` и хостов `x-ald-host-mac`:

```
confidentiality:categories:capabilities:integrity
```

Атрибут `x-ald-url-glob` принимает значения `TRUE` или `FALSE`. Если `TRUE` — значение пути трактуется как glob-выражение (например, `/api/**`), а не точный URL.

Атрибут `x-ald-url-description` является необязательным и содержит произвольное текстовое описание ресурса.

### Выдать права на чтение

Для работы с созданными ранее атрибутами требуется выдать разрешения. Например, выдать разрешение на чтение, поиск и сравнение атрибутов для всех можно так:

```bash
ipa permission-add "Read custom URL security context" \
  --type=service \
  --right={read,search,compare} \
  --attrs={x-ald-url-mac,x-ald-url-glob,x-ald-url-description} \
  --bindtype=all
```
