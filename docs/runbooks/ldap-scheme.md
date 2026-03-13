# Расширение схемы LDAP

## Добавление меток узлам

Чтобы добавить узлам атрибуты мандатного управления доступом:

1. Файл [74x-ald-host-mac.ldif](../../74x-ald-host-mac.ldif) вместе с его содержимым создайте на сервере со службой каталога по пути `/etc/dirsrv/slapd-ALD-COMPANY-LAN/schema/74x-ald-host-mac.ldif` (путь может отличаться в зависимости от realm вашего домена)
2. Перезапустите службу каталогов:

    ```bash
    systemctl restart dirsrv@ALD-COMPANY-LAN.service
    ```

Назначить созданные ранее атрибуты узла можно следующей командой (заменив `${host}` на FQDN узла в домене):

```bash
ipa host-mod ${host} \
  --addattr=x-ald-host-mac="2:0x1:0:0x0" \
  --addattr=x-ald-host-mic-level=0x3F \
  --addattr=x-ald-host-caps=0
```

Формат атрибутов аналогичен формату атрибутов пользователей `x-ald-user-mac`, `x-ald-user-mic-level` и `x-ald-user-caps`

## Создание новой сущности

