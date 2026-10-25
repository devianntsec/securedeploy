variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "project" {
  type    = string
  default = "securedeploy"
}

variable "instance_type" {
  type    = string
  default = "t3.micro"
}

variable "vpc_cidr" {
  type    = string
  default = "10.42.0.0/24"
}

variable "allowed_ingress_cidrs" {
  description = "CIDRs que pueden llegar a la API (puerto 8000). Sin default a propósito: debes elegirlos."
  type        = list(string)
}

variable "admin_cidr" {
  description = "CIDR con acceso SSH (para Ansible). Vacío = SSH cerrado y acceso solo por SSM."
  type        = string
  default     = ""
}

variable "ssh_key_name" {
  description = "Nombre del key pair EC2 existente (solo necesario si admin_cidr no está vacío)."
  type        = string
  default     = ""
}

variable "github_repo" {
  description = "owner/repo autorizado a desplegar vía OIDC, p. ej. devianntsec/securedeploy"
  type        = string
}

variable "create_github_oidc_provider" {
  description = "false si la cuenta ya tiene el proveedor OIDC de GitHub."
  type        = bool
  default     = true
}
