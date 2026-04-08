locals {
  realm          = var.realm != "" ? var.realm : upper(var.domain)
  dc_fqdn        = "${var.dc_name}.${var.domain}"
  client_fqdn    = "${var.client_name}.${var.domain}"
  ssh_keys       = "${var.ssh_user}:${var.ssh_public_key}"
  dc_internal_ip = cidrhost(yandex_vpc_subnet.freeipa.v4_cidr_blocks[0], 10) # e.g. 10.10.10.10 for 10.10.10.0/24
}
