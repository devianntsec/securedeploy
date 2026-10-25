# Solo se crea el contenedor del secreto. El VALOR nunca pasa por Terraform ni por el state:
#   aws secretsmanager put-secret-value --secret-id <secret_arn> --secret-string '{"api_key":"TU_CLAVE_NVD"}'
resource "aws_secretsmanager_secret" "nvd_api_key" {
  name                    = "${var.project}/nvd-api-key"
  description             = "API key de la NVD para SecureDeploy"
  kms_key_id              = aws_kms_key.this.arn
  recovery_window_in_days = 7
}

resource "aws_secretsmanager_secret_version" "placeholder" {
  secret_id     = aws_secretsmanager_secret.nvd_api_key.id
  secret_string = jsonencode({ api_key = "REPLACE_ME" })

  # Evita que un apply posterior pise la clave real que cargaste con la CLI.
  lifecycle {
    ignore_changes = [secret_string]
  }
}
