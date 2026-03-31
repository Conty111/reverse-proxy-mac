#!/usr/bin/env bash
set -euo pipefail

# Конфигурация
DOMAIN="${DOMAIN:-ald.company.lan}"
REALM="${REALM:-ALD.COMPANY.LAN}"
DIRSRV_INSTANCE="$(echo "$REALM" | tr '.' '-')"
SCHEMA_DIR="/etc/dirsrv/slapd-$DIRSRV_INSTANCE/schema"
DC_HOST="${DC_HOST:-dc-1.${DOMAIN}}"
# Пароль Directory Manager нужен для записи в cn=config (недоступно через GSSAPI)
DM_PASSWORD="${DM_PASSWORD:-}"

BASE_DN="$(echo "$REALM" | tr '[:upper:]' '[:lower:]' | awk -F. '{sep=""; for(i=1;i<=NF;i++){printf "%sdc=%s", sep, $i; sep=","}; print ""}')"

AUTH_SERVER_HOST="mac-authserver.$DOMAIN"
KEYTAB_PATH="${KEYTAB_PATH:-/tmp/mac-authserver.keytab}"

TEST_USER_LOW="testuser-low"
TEST_USER_MID="testuser-mid"
TEST_USER_HIGH="testuser-high"
TEST_USER_PASSWORD="TestPass123!"

TEST_HOST_LOW="app-low.$DOMAIN"
TEST_HOST_MID="app-mid.$DOMAIN"
TEST_HOST_HIGH="app-high.$DOMAIN"

try() { "$@" || true; }

# 1. Схемы и перезапуск dirsrv
cat > "$SCHEMA_DIR/74x-ald-host-mac.ldif" <<'LDIF'
dn: cn=schema
attributeTypes: ( 1.3.6.1.4.1.32702.1.1.2.1 NAME 'x-ald-host-mac' DESC 'Complex MAC label for a host (confidentiality-min:categories-min:confidentiality-max:categories-max)' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.32702.1.1.2.2 NAME 'x-ald-host-mic-level' DESC 'Maximum allowed integrity level (categories) for a host' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
objectClasses: ( 1.3.6.1.4.1.32702.2.2 NAME 'aldHostContext' DESC 'Auxiliary class for host MAC/MIC context' SUP top AUXILIARY MUST ( x-ald-host-mac $ x-ald-host-mic-level ) )
LDIF

cat > "${SCHEMA_DIR}/74x-ald-uri-mac.ldif" <<'LDIF'
dn: cn=schema
attributeTypes: ( 1.3.6.1.4.1.32702.1.1.3.1 NAME 'x-ald-uri-mac' DESC 'Complex MAC label for a URI resource (confidentiality-min:categories-min:confidentiality-max:categories-max)' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.32702.1.1.3.2 NAME 'x-ald-uri-mic-level' DESC 'Maximum allowed integrity level (categories) for a URI resource' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.32702.1.1.3.3 NAME 'x-ald-uri-match-type' DESC 'URI path matching type: exact (default), prefix, or regex' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.32702.1.1.3.4 NAME 'x-ald-uri-description' DESC 'Human-readable description of the URI resource' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.32702.1.1.3.5 NAME 'x-ald-uri-path' DESC 'URI path pattern (exact path, prefix, or regex depending on x-ald-uri-match-type)' EQUALITY caseExactMatch SUBSTR caseExactSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.32702.1.1.3.6 NAME 'x-ald-uri-service-ref' DESC 'DN of a HTTP service principal this URI MAC rule is bound to' EQUALITY distinguishedNameMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )
objectClasses: ( 1.3.6.1.4.1.32702.2.4 NAME 'aldURIMACRule' DESC 'URI-based MAC rule entry; bound to HTTP service principals; carries a MAC label for the URI path' SUP top STRUCTURAL MUST ( cn $ x-ald-uri-mac $ x-ald-uri-path ) MAY ( x-ald-uri-mic-level $ x-ald-uri-match-type $ x-ald-uri-service-ref $ x-ald-uri-description ) )
LDIF

systemctl restart "dirsrv@${DIRSRV_INSTANCE}.service"

# 2. Referential integrity для URI-атрибутов
# cn=plugins,cn=config доступен на запись только cn=Directory Manager (не через GSSAPI)
if [[ -z "$DM_PASSWORD" ]]; then
    echo "ERROR: DM_PASSWORD is required for modifying cn=config. Set it via: export DM_PASSWORD=<password>" >&2
    exit 1
fi
try ldapmodify -x -H "ldap://${DC_HOST}" -D "cn=Directory Manager" -w "$DM_PASSWORD" <<'LDIF'
dn: cn=referential integrity postoperation,cn=plugins,cn=config
changetype: modify
add: referint-membership-attr
referint-membership-attr: x-ald-uri-service-ref
LDIF

# 3. Сервисный принципал + роль
try ipa service-add "HTTP/${AUTH_SERVER_HOST}@${REALM}"
try ipa role-add "User Attribute Reader" --desc="Can read user attributes"
try ipa role-add-privilege "User Attribute Reader" --privileges="User Administrators"
try ipa role-add-member "User Attribute Reader" --services="HTTP/${AUTH_SERVER_HOST}@${REALM}"

# 4. Разрешения на чтение атрибутов
try ipa permission-add "Read host security context" \
    --type=host --right={read,search,compare} \
    --attrs={x-ald-host-mac,x-ald-host-mic-level} --bindtype=all

# 5. Тестовые пользователи
create_user() {
    local login="$1" last="$2" mac="$3" mic="$4"
    try ipa user-add "$login" --first="Test" --last="$last" \
        --password <<< "${TEST_USER_PASSWORD}"$'\n'"${TEST_USER_PASSWORD}"
    try ipa user-mod "$login" --setattr=x-ald-user-mac="$mac"
    try ipa user-mod "$login" --setattr=x-ald-user-mic-level="$mic"
}
create_user "$TEST_USER_LOW"  "UserLow"  "0:0x0:1:0x0"  "0x0"
create_user "$TEST_USER_MID"  "UserMid"  "1:0x3:2:0x3"  "0x1"
create_user "$TEST_USER_HIGH" "UserHigh" "2:0xFF:3:0xFF" "0x3"

# 6. Тестовые хосты
create_host() {
    local fqdn="$1" mac="$2" mic="$3"
    try ipa host-add "$fqdn" --force
    try ipa host-mod "$fqdn" --addattr=objectClass=aldHostContext
    try ipa host-mod "$fqdn" --setattr=x-ald-host-mac="$mac"
    try ipa host-mod "$fqdn" --setattr=x-ald-host-mic-level="$mic"
}
create_host "$TEST_HOST_LOW"  "0:0x0:1:0x0"  "0x0"
create_host "$TEST_HOST_MID"  "1:0x3:2:0x3"  "0x1"
create_host "$TEST_HOST_HIGH" "2:0xFF:3:0xFF" "0x3"

# 7. HTTP-сервисы для тестовых хостов
for host in "$TEST_HOST_LOW" "$TEST_HOST_MID" "$TEST_HOST_HIGH"; do
    try ipa service-add "HTTP/${host}@${REALM}" --force
done

# 8. Тестовые URI MAC-правила

# Контейнер для URI MAC-правил
ldapadd -Y GSSAPI <<LDIF || true
dn: cn=uri-mac-rules,cn=accounts,${BASE_DN}
objectClass: top
objectClass: nsContainer
cn: uri-mac-rules
LDIF

# aldURIMACRule entries live under cn=uri-mac-rules,cn=accounts,<base>,
# which is NOT a standard IPA object type. We must grant access via a raw
# LDAP ACI on the container rather than an IPA permission (which only covers
# known object types like host/service/user).
# The ACI grants read/search/compare on all attributes of aldURIMACRule
# entries to any authenticated principal (all).
ldapmodify -Y GSSAPI -H "ldap://${DC_HOST}" <<LDIF || true
dn: cn=uri-mac-rules,cn=accounts,${BASE_DN}
changetype: modify
add: aci
aci: (targetattr="*")(targetfilter="(objectClass=aldURIMACRule)")(version 3.0; acl "Read URI MAC rules"; allow (read,search,compare) userdn="ldap:///all";)
LDIF

SVC_BASE="cn=services,cn=accounts,${BASE_DN}"
SVC_LOW="krbprincipalname=HTTP/${TEST_HOST_LOW}@${REALM},${SVC_BASE}"
SVC_MID="krbprincipalname=HTTP/${TEST_HOST_MID}@${REALM},${SVC_BASE}"
SVC_HIGH="krbprincipalname=HTTP/${TEST_HOST_HIGH}@${REALM},${SVC_BASE}"
URI_BASE="cn=uri-mac-rules,cn=accounts,${BASE_DN}"

# Правило: точное совпадение /api/secret — уровень 2-3, привязано к app-mid
ldapadd -Y GSSAPI <<LDIF || true
dn: cn=rule-api-secret,${URI_BASE}
objectClass: top
objectClass: aldURIMACRule
cn: rule-api-secret
x-ald-uri-path: /api/secret
x-ald-uri-mac: 2:0x1:3:0xFF
x-ald-uri-service-ref: ${SVC_MID}
x-ald-uri-description: Exact match /api/secret - level 2+
LDIF

# Правило: префиксное совпадение /api/admin — уровень 1-2, привязано к app-mid и app-high
ldapadd -Y GSSAPI <<LDIF || true
dn: cn=rule-api-admin,${URI_BASE}
objectClass: top
objectClass: aldURIMACRule
cn: rule-api-admin
x-ald-uri-path: /api/admin
x-ald-uri-mac: 1:0x0:2:0x3
x-ald-uri-match-type: prefix
x-ald-uri-service-ref: ${SVC_MID}
x-ald-uri-service-ref: ${SVC_HIGH}
x-ald-uri-description: Prefix match /api/admin/* - level 1-2
LDIF

# Правило: regex-совпадение /api/v<N>/users/<N> — уровень 1-2, привязано к app-mid
ldapadd -Y GSSAPI <<LDIF || true
dn: cn=rule-api-users-regex,${URI_BASE}
objectClass: top
objectClass: aldURIMACRule
cn: rule-api-users-regex
x-ald-uri-path: /api/v[0-9]+/users/[0-9]+
x-ald-uri-mac: 1:0x1:2:0x1
x-ald-uri-match-type: regex
x-ald-uri-service-ref: ${SVC_MID}
x-ald-uri-description: Regex match /api/v*/users/* - level 1-2
LDIF

# Правило: префиксное совпадение /api/reports — уровень 2-3, привязано к app-low, app-mid и app-high
ldapadd -Y GSSAPI <<LDIF || true
dn: cn=rule-api-reports,${URI_BASE}
objectClass: top
objectClass: aldURIMACRule
cn: rule-api-reports
x-ald-uri-path: /api/reports
x-ald-uri-mac: 2:0x0:3:0xFF
x-ald-uri-match-type: prefix
x-ald-uri-service-ref: ${SVC_LOW}
x-ald-uri-service-ref: ${SVC_MID}
x-ald-uri-service-ref: ${SVC_HIGH}
x-ald-uri-description: Prefix match /api/reports/* - level 2-3
LDIF

# 9. Keytab (опционально; включается через RECREATE_KEYTAB=1)
RECREATE_KEYTAB="${RECREATE_KEYTAB:-0}"
if [[ "$RECREATE_KEYTAB" == "1" ]]; then
    rm -f "$KEYTAB_PATH"
    for host in "$AUTH_SERVER_HOST" "$TEST_HOST_LOW" "$TEST_HOST_MID" "$TEST_HOST_HIGH"; do
        ipa-getkeytab -s "$DC_HOST" -p "HTTP/${host}@${REALM}" -k "$KEYTAB_PATH"
    done
    chmod 644 "$KEYTAB_PATH"
    echo "Готово. Keytab: ${KEYTAB_PATH}"
else
    echo "Готово. Keytab не пересоздавался (RECREATE_KEYTAB=0). Для пересоздания запустите с RECREATE_KEYTAB=1."
fi
