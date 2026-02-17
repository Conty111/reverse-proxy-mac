Copy-pasyt актуален для домена ald.company.lan. Для других доменов заменить на свой.

### Сбрасываем пароль админа LDAP:

1. 
```bash
systemctl stop dirsrv@ALD-COMPANY-LAN
```

2. 
```bash
/usr/bin/pwdhash <новый_пароль_для_админа_LDAP>
```

3.
В файле `/etc/dirsrv/slapd-ALD-COMPANY-LAN/dse.ldif` подставить сгенерированный хэш в параметр **nsslapd-rootpw**

4. 
```bash
systemctl start dirsrv*
```
```bash
systemctl start dirsrv*
```

### Сбрасываем пароль админа ALD Pro (admin):

1.
```bash
sudo ldappasswd -ZZ -D 'cn=Directory Manager' -W -S uid=admin,cn=users,cn=accounts,dc=ald,dc=company,dc=lan -H ldap://dc-1.ald.company.lan

New password: <новый_пароль_для_admin>
Re-enter new password: <новый_пароль_для_admin>
Enter LDAP Password: <пароль_админа_LDAP>
```

### Проверка
```bash
kinit admin
```
