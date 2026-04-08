# =============================================================================
# FreeIPA Client Host VM — joins the FreeIPA domain
# =============================================================================

resource "yandex_compute_instance" "client" {
  name        = var.client_name
  hostname    = local.client_fqdn
  platform_id = "standard-v4a"
  zone        = var.zone
  folder_id   = var.folder_id

  # Client must wait for DC to be created first
  depends_on = [yandex_compute_instance.dc]

  resources {
    cores         = 2
    memory        = 2
    core_fraction = 100
  }

  boot_disk {
    initialize_params {
      name       = "${var.client_name}-boot"
      type       = "network-ssd"
      size       = 30
      block_size = 4096
      image_id   = var.image_id
    }
    auto_delete = true
  }

  network_interface {
    subnet_id          = yandex_vpc_subnet.freeipa.id
    nat                = true
    security_group_ids = [yandex_vpc_security_group.freeipa_client.id]
  }

  metadata = {
    user-data = templatefile("${path.module}/cloud-init/freeipa-client.yaml.tftpl", {
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
