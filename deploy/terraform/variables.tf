variable "cloud_id" {
  description = "Yandex Cloud ID"
  type        = string
}

variable "folder_id" {
  description = "Yandex Cloud Folder ID"
  type        = string
}

variable "zone" {
  description = "Yandex Cloud availability zone"
  type        = string
  default     = "ru-central1-a"
}
variable "network_id" {
  description = "ID of the network"
  type        = string
}

variable "subnet_name" {
  description = "Name of the subnet"
  type        = string
  default     = "freeipa-subnet"
}

variable "subnet_cidr" {
  description = "CIDR block for the subnet"
  type        = list(string)
  default     = ["10.10.10.0/24"]
}

variable "domain" {
  description = "FreeIPA domain name (e.g. ald.company.lan)"
  type        = string
  default     = "ald.company.lan"
}

variable "realm" {
  description = "Kerberos realm (uppercase domain, e.g. ALD.COMPANY.LAN). If empty, derived from domain."
  type        = string
  default     = ""
}

variable "ssh_user" {
  description = "SSH username for VM access"
  type        = string
  default     = "admin"
}

variable "ssh_public_key" {
  description = "SSH public key for VM access"
  type        = string
  sensitive   = true
}

variable "dc_name" {
  description = "Name of the domain controller VM"
  type        = string
  default     = "dc-1"
}

variable "client_name" {
  description = "Name of the client host VM"
  type        = string
  default     = "host-1"
}

variable "image_id" {
  description = "Yandex Cloud image ID for Astra Linux SE (e.g. fd8e1odrt1pkl6kkffbn)"
  type        = string
}
