# Расширение схемы LDAP

## Добавление меток узлам

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
level:categories:capabilities:integrity
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

