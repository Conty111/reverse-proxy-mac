# Enabling TLS connection with LDAP

LDAP usually uses TLS connection on **636** port.

1. Export certificate by terminal
    ```bash
    HOST=<address>
    PORT=<port>
    openssl s_client -connect ${HOST}:${PORT} -showcerts < /dev/null 2>/dev/null | \
    openssl x509 -outform PEM > /etc/ssl/certs/company-ca.pem
    ```

    Example:

    ```bash
    HOST=dc-1.ald.company.lan
    PORT=636
    openssl s_client -connect ${host}:${port} -showcerts < /dev/null 2>/dev/null | \
    openssl x509 -outform PEM > /etc/ssl/certs/company-ca.pem
    ```

    Or get certificate in another way

2. Configuration settings

    ```json
    "tls": true, // use tls connection
    "tls_skip_verify": false,
    "tls_ca_cert_file": "/path/to/certificate" // write your certificate path
    ```
