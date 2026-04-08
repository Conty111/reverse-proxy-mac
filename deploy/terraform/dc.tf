# =============================================================================
# FreeIPA Domain Controller VM
# =============================================================================

resource "yandex_compute_instance" "dc" {
  name        = var.dc_name
  hostname    = local.dc_fqdn
  platform_id = "standard-v4a"
  zone        = var.zone
  folder_id   = var.folder_id

  resources {
    cores         = 2
    memory        = 4
    core_fraction = 100
  }

  boot_disk {
    initialize_params {
      name       = "${var.dc_name}-boot"
      type       = "network-ssd"
      size       = 30
      block_size = 4096
      image_id   = var.image_id
    }
    auto_delete = true
  }

  network_interface {
    subnet_id          = yandex_vpc_subnet.freeipa.id
    ip_address         = local.dc_internal_ip
    nat                = true
    nat_ip_address     = yandex_vpc_address.dc_external.external_ipv4_address[0].address
    security_group_ids = [yandex_vpc_security_group.freeipa_dc.id]
  }

  metadata = {
    user-data = templatefile("${path.module}/cloud-init/freeipa-server.yaml.tftpl", {
      ssh_user       = var.ssh_user
      ssh_public_key = var.ssh_public_key
    })
    ssh-keys = local.ssh_keys
  }

  scheduling_policy {
    preemptible = false
  }

  allow_stopping_for_update = true
}
