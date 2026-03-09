# Configuration

```
{
  "server": { // grpc server settings
    "grpc_port": 9001, // port listen to
    "host": "0.0.0.0" // address listen to
  },
  "log": { // loggign settings
    "level": "debug",
    "json_format": false
  },
  "ldap": { // ldap integration settings
    "kerberos": { // kerberos integration settings
      "keytab": "/etc/mac-authserver.keytab", // keytab file path
      "principal": "HTTP/mac-authserver.ald.company.lan", // Kerberos principal (without realm)
      "realm": "ALD.COMPANY.LAN", // Domain realm
      "config_path": "/etc/krb5.conf" // Kerberos configuration file path
    },
    "port": 636, // ldap port
    "host": "dc-1.ald.company.lan", // ldap address
    "tls": true, // use tls connection
    "tls_skip_verify": true,
    "tls_ca_cert_file": "" // path to CA certificate file to trust ldap's certificate
  }
}
```