# =============================================================================
# Domain Controller outputs
# =============================================================================

output "dc_internal_ip" {
  description = "Internal IP address of the FreeIPA domain controller"
  value       = local.dc_internal_ip
}

output "dc_external_ip" {
  description = "Reserved external (public) IP address of the FreeIPA domain controller"
  value       = yandex_vpc_address.dc_external.external_ipv4_address[0].address
}

output "dc_fqdn" {
  description = "FQDN of the FreeIPA domain controller"
  value       = local.dc_fqdn
}

output "dc_instance_id" {
  description = "Instance ID of the FreeIPA domain controller"
  value       = yandex_compute_instance.dc.id
}

# =============================================================================
# Client Host outputs
# =============================================================================

output "client_fqdn" {
  description = "FQDN of the client host"
  value       = local.client_fqdn
}

output "client_instance_id" {
  description = "Instance ID of the client host"
  value       = yandex_compute_instance.client.id
}

# =============================================================================
# Domain info
# =============================================================================

output "domain" {
  description = "FreeIPA domain name"
  value       = var.domain
}

output "realm" {
  description = "Kerberos realm"
  value       = local.realm
}

# =============================================================================
# Connection instructions
# =============================================================================

output "ssh_to_dc" {
  description = "SSH command to connect to the domain controller"
  value       = "ssh ${var.ssh_user}@${yandex_vpc_address.dc_external.external_ipv4_address[0].address}"
}

output "ssh_to_client" {
  description = "SSH command to connect to the client host"
  value       = "ssh ${var.ssh_user}@${yandex_compute_instance.client.network_interface[0].nat_ip_address}"
}

output "freeipa_web_ui" {
  description = "FreeIPA Web UI URL"
  value       = "https://${local.dc_fqdn}"
}
