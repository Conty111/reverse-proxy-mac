# Reverse proxy MAC

Обратный прокси-сервер с поддержкой мандатного управления доступом. Реализуется в рамках проекта Астра Стипендии 2026.

## Архитектура

- [Обзор дизайна системы](./docs/design.md)
- [Модель управления доступом](./docs/access.md)

## Использование

У вас должен быть развернут контроллер домена ALD Pro или FreeIPA и быть доступ к серверу контроллера домена.

- [Развертывание](./docs/runbooks/setup.md)

## Пошаговые инструкции

Полезные инструкции по развертыванию и настройке контроллера домена.

- [Расширение схемы LDAP в командной строке](./docs/runbooks/ldap-scheme.md)
- [Обеспечение TLS соединения с LDAP](./docs/runbooks/tls.md)
- [Сброс пароля администратора контроллера домена](./docs/runbooks/dc-reset-password.md)
- [Развертывание контроллера домена ALD Pro 3.0.0](https://www.aldpro.ru/professional/ALD_Pro_Module_02/ALD_Pro_deployment.html#aldpro-dc-packages-install)
- [Развертывание контроллера домена FreeIPA на Astra Linux](https://wiki.astralinux.ru/pages/viewpage.action?pageId=27362143)
- [Ввод Astra Linux в домен FreeIPA](https://wiki.astralinux.ru/pages/viewpage.action?pageId=60359750)
- [Чтение пользовательских атрибутов (настройка прав)](https://wiki.astralinux.ru/pages/viewpage.action?pageId=153488486)