# Arquitectura

```
Internet ─▶ SG (8000, solo CIDRs permitidos) ─▶ EC2 Ubuntu 22.04 (IMDSv2, EBS cifrado)
                                                  ├─ systemd: securedeploy.service
                                                  │    └─ docker run (read-only, cap-drop ALL, límites)
                                                  ├─ Falco (modern eBPF) + auditd
                                                  └─ UFW + fail2ban + sysctl + SSH endurecido
AWS: VPC + Flow Logs ─ KMS ─ Secrets Manager (API key NVD) ─ ECR (tags inmutables) ─ IAM mínimo ─ OIDC GitHub
CI/CD: lint → tests → Bandit/Semgrep/pip-audit → Trivy(fs, imagen, IaC) → push ECR → SSM restart → smoke test
```

## Decisiones clave
| Decisión | Motivo | Trade-off |
|----------|--------|-----------|
| EC2 + Docker en lugar de ECS/Fargate | Permite demostrar hardening de host con Ansible/CIS/Falco/auditd | Más superficie operativa que un servicio gestionado |
| Secreto leído por el **host** y pasado por env | El contenedor no necesita credenciales AWS (IMDS hop limit 1) | La clave es visible para root del host; el código también soporta lectura directa vía boto3 (`SD_NVD_SECRET_ID`) para ECS/Lambda |
| Deploy por SSM en vez de SSH | No hay puerto 22 abierto en CI | Requiere agente SSM y permisos IAM |
| Tags de ECR inmutables (SHA) | Trazabilidad y anti-sobrescritura | No existe `latest` |
| Lynis para la métrica antes/después | Gratis, reproducible y numérico | No equivale a certificación CIS; el rol CIS se aplica aparte (`cis.yml`) |
| Docker publica puertos vía iptables y salta UFW | — | El perímetro real es el Security Group; UFW es defensa en profundidad |
