output "aws_region" {
  value = var.aws_region
}

output "instance_id" {
  value = aws_instance.app.id
}

output "public_ip" {
  value = aws_eip.app.public_ip
}

output "ecr_repository_url" {
  value = aws_ecr_repository.app.repository_url
}

output "secret_arn" {
  value = aws_secretsmanager_secret.nvd_api_key.arn
}

output "github_actions_role_arn" {
  value = aws_iam_role.gha.arn
}

output "put_secret_command" {
  value = "aws secretsmanager put-secret-value --secret-id ${aws_secretsmanager_secret.nvd_api_key.arn} --secret-string '{\"api_key\":\"TU_CLAVE_NVD\"}'"
}
