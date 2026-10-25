#!/usr/bin/env bash
# Genera el inventario y variables de Ansible a partir de `terraform output`.
set -euo pipefail
cd "$(dirname "$0")/../terraform"
ip=$(terraform output -raw public_ip)
repo=$(terraform output -raw ecr_repository_url)
region=$(terraform output -raw aws_region)
secret=$(terraform output -raw secret_arn)
cat > ../ansible/inventory.ini <<INV
[securedeploy]
${ip} ansible_user=ubuntu
INV
cat > ../ansible/group_vars/terraform.yml <<VARS
---
# Generado por scripts/gen_inventory.sh - no editar
aws_region: ${region}
ecr_repository_url: ${repo}
ecr_registry: ${repo%%/*}
secret_id: ${secret}
VARS
echo "Inventario generado para ${ip}"
