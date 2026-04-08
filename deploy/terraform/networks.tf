# =============================================================================
# VPC Network
# =============================================================================

data "yandex_vpc_network" "default" {
  network_id = var.network_id
}

resource "yandex_vpc_subnet" "freeipa" {
  name           = var.subnet_name
  zone           = var.zone
  network_id     = data.yandex_vpc_network.default.id
  v4_cidr_blocks = var.subnet_cidr
}

# =============================================================================
# Security Group — FreeIPA domain controller
# =============================================================================

resource "yandex_vpc_security_group" "freeipa_dc" {
  name       = "freeipa-dc-sg"
  network_id = data.yandex_vpc_network.default.id

  # --- Ingress ---

  # SSH
  ingress {
    protocol       = "TCP"
    port           = 22
    v4_cidr_blocks = ["0.0.0.0/0"]
    description    = "SSH"
  }

  # HTTP / HTTPS (FreeIPA Web UI)
  ingress {
    protocol       = "TCP"
    port           = 80
    v4_cidr_blocks = ["0.0.0.0/0"]
    description    = "HTTP"
  }

  ingress {
    protocol       = "TCP"
    port           = 443
    v4_cidr_blocks = ["0.0.0.0/0"]
    description    = "HTTPS (FreeIPA Web UI)"
  }

  # DNS
  ingress {
    protocol       = "TCP"
    port           = 53
    v4_cidr_blocks = [var.subnet_cidr[0]]
    description    = "DNS TCP"
  }

  ingress {
    protocol       = "UDP"
    port           = 53
    v4_cidr_blocks = [var.subnet_cidr[0]]
    description    = "DNS UDP"
  }

  # Kerberos
  ingress {
    protocol       = "TCP"
    port           = 88
    v4_cidr_blocks = [var.subnet_cidr[0]]
    description    = "Kerberos TCP"
  }

  ingress {
    protocol       = "UDP"
    port           = 88
    v4_cidr_blocks = [var.subnet_cidr[0]]
    description    = "Kerberos UDP"
  }

  # Kerberos kpasswd
  ingress {
    protocol       = "TCP"
    port           = 464
    v4_cidr_blocks = [var.subnet_cidr[0]]
    description    = "Kerberos kpasswd TCP"
  }

  ingress {
    protocol       = "UDP"
    port           = 464
    v4_cidr_blocks = [var.subnet_cidr[0]]
    description    = "Kerberos kpasswd UDP"
  }

  # LDAP / LDAPS
  ingress {
    protocol       = "TCP"
    port           = 389
    v4_cidr_blocks = [var.subnet_cidr[0]]
    description    = "LDAP"
  }

  ingress {
    protocol       = "TCP"
    port           = 636
    v4_cidr_blocks = [var.subnet_cidr[0]]
    description    = "LDAPS"
  }

  # NTP
  ingress {
    protocol       = "UDP"
    port           = 123
    v4_cidr_blocks = [var.subnet_cidr[0]]
    description    = "NTP"
  }

  # ICMP (ping)
  ingress {
    protocol       = "ICMP"
    v4_cidr_blocks = [var.subnet_cidr[0]]
    description    = "ICMP"
  }

  # --- Egress ---

  egress {
    protocol       = "ANY"
    v4_cidr_blocks = ["0.0.0.0/0"]
    description    = "Allow all outbound"
  }
}

# =============================================================================
# Security Group — FreeIPA client host
# =============================================================================

resource "yandex_vpc_security_group" "freeipa_client" {
  name       = "freeipa-client-sg"
  network_id = data.yandex_vpc_network.default.id

  # SSH
  ingress {
    protocol       = "TCP"
    port           = 22
    v4_cidr_blocks = ["0.0.0.0/0"]
    description    = "SSH"
  }

  # ICMP
  ingress {
    protocol       = "ICMP"
    v4_cidr_blocks = [var.subnet_cidr[0]]
    description    = "ICMP"
  }

  # All outbound
  egress {
    protocol       = "ANY"
    v4_cidr_blocks = ["0.0.0.0/0"]
    description    = "Allow all outbound"
  }
}

# =============================================================================
# Reserved IP addresses for DC
# =============================================================================

# Reserved external (public) IP address for DC
resource "yandex_vpc_address" "dc_external" {
  name = "${var.dc_name}-external-ip"

  external_ipv4_address {
    zone_id = var.zone
  }
}
