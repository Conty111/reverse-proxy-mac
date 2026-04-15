# Развертывание

## Подготовка контроллера домена

На примере FreeIPA.

### Расширение схемы LDAP

1. Для узлов: [установка](./ldap-scheme.md#установка-схемы)
2. Для URI правил: [установка](./ldap-scheme.md#установка-схемы-1)

### Создание HTTP служб

Для каждого узла, к которому доступ по HTTP должен быть авторизованным, необходимо создать HTTP службу. Это нужно для того, чтобы клиент мог получить Kerberos билет для веб-сервиса.

Файл с ключами keytab должен содержать ключи для **всех служб**, к которым сервис будет проверять доступ. Это необходимо для расшифровки билета пользователя.

1. Создать сервис (HTTP службу) в контроллере домена
    ```bash
    ipa service-add HTTP/host1.ald.company.lan
    ```

    > #### Для тестирования
    > Если возникает ошибка из-за отсутствия хоста, можно добавить хост командой
    > ```bash
    > ipa host-add host1.ald.company.lan --force
    > ```
    > и создать сервис с флагом `--force`
    > ```bash
    > ipa service-add HTTP/host1.ald.company.lan --force
    > ```

2. Выдать права на чтение пользовательских атрибутов

    ```bash
    ipa permission-add "Read Users Attributes" \
    --type=service \
    --right={read,search,compare} \
    --attrs={cn,uid,x-ald-user-mac,x-ald-user-mic-level}

    ipa privilege-add "UsersAttributeReaderPrivilege" --desc="Can read users attributes"

    ipa privilege-add-permission "UsersAttributeReaderPrivilege" --permissions="Read Users Attributes"

    ipa role-add "User Attribute Reader" --desc="Can read users attributes"
    
    ipa role-add-privilege "User Attribute Reader" --privileges="UsersAttributeReaderPrivilege"
    ```
    ```bash
    ipa role-add-member "User Attribute Reader" --services=HTTP/host1.ald.company.lan@ALD.COMPANY.LAN
    ```

3. Выдать права на чтение атрибутов узлов: [инструкция](./ldap-scheme.md#выдача-прав)

4. Выдать права на чтение атрибутов URI правил: [инструкция](./ldap-scheme.md#выдача-прав-1)

5. Выписать Kerberos ключ для сервиса

    ```bash
    ipa-getkeytab -s dc-1.ald.company.lan -p HTTP/host1.ald.company.lan -k /tmp/host1.keytab
    ```

6. Файл ключа скопировать испрользовать в конфигурации сервиса (указать путь к файлу в `ldap.kerberos.keytab`)
