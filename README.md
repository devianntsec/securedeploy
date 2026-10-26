# SecureDeploy

API en FastAPI que consulta la [NVD](https://nvd.nist.gov/developers/vulnerabilities) (CVE por ID o búsqueda por palabra clave y severidad), desplegada en AWS con **seguridad como código**: pipeline con gates, Terraform, Ansible (hardening + CIS), gestión de secretos, detección (Falco + auditd) y documentación de threat modeling e incident response.

| Capacidad | Dónde |
|---|---|
| App FastAPI + caché + tests (17, cobertura ~98 %) | `app/`, `tests/` |
| Dockerfile multi-stage, usuario no-root, healthcheck | `Dockerfile` |
| CI: ruff, hadolint, pytest, Bandit, Semgrep, pip-audit, Trivy (fs/imagen/IaC), ansible-lint | `.github/workflows/ci.yml` |
| Deploy: OIDC → ECR (tags inmutables) → SSM → smoke test | job `deploy` |
| AWS con Terraform: VPC, Flow Logs, KMS, Secrets Manager, ECR, EC2 (IMDSv2), IAM mínimo, OIDC | `terraform/` |
| Hardening del host: SSH, sysctl, UFW, fail2ban, auditd, Docker, Falco | `ansible/` |
| CIS Ubuntu 22.04 (ansible-lockdown) y reporte de hardening (Lynis antes/después) | `ansible/cis.yml`, `ansible/audit.yml`, `scripts/metrics.py` |
| Reglas de detección reutilizables | `detection/falco/`, `detection/auditd/` |
| STRIDE, playbook de IR, arquitectura, borrador del write-up | `docs/` |

## Endpoints
`GET /health` · `GET /cves/{CVE-ID}` · `GET /cves?keyword=log4j&severity=CRITICAL&limit=10` · `/docs` (OpenAPI)

## Desarrollo local
```bash
make install && make lint test sast
SD_NVD_API_KEY=tu_clave make run     # la clave es opcional; sin ella la NVD limita ~5 req/30 s
```
Variables (`SD_`): `NVD_API_KEY`, `NVD_SECRET_ID` (Secrets Manager), `AWS_REGION`, `CACHE_TTL_SECONDS`, `MAX_RESULTS`.

## Despliegue en AWS (orden)
```bash
cd terraform && cp terraform.tfvars.example terraform.tfvars   # edita CIDRs y github_repo
make tf-init tf-plan tf-apply
# 1) carga la clave real (no pasa por el state):
$(cd terraform && terraform output -raw put_secret_command)
# 2) en GitHub: Settings → Variables → AWS_DEPLOY_ENABLED=true, AWS_REGION, AWS_ROLE_ARN,
#    ECR_REPOSITORY, EC2_INSTANCE_ID, APP_HOST (salen de `terraform output`)
# 3) host:
make inventory && cd ansible && ansible-galaxy collection install -r requirements.yml
make audit-before          # métrica "antes"
make harden IMAGE_TAG=<sha-ya-publicado-en-ECR>
make audit-after && make metrics
make cis                   # opcional: rol CIS Level 1 (haz snapshot de la VM: --check no simula el rol completo)
```

## Falco: reglas y pruebas
`detection/falco/securedeploy_rules.yaml` tiene 26 reglas con ID estable (SD-C## contenedor, SD-H## host, SD-X## ambos), autocontenidas y afinables por listas `sd_*`.

```bash
make falco-validate                  # local/CI: valida con el binario real de Falco (falco -V)
# en el EC2, tras `make harden`:
sudo systemctl status falco-modern-bpf
sudo ./scripts/test_falco.sh         # dispara cada regla de forma segura -> PASS/FAIL
sudo ./scripts/test_falco.sh SD-C01  # una sola
jq -c '{t:.time,r:.rule,p:.priority,o:.output}' /var/log/falco/events.json | tail
```
Durante `make harden` es normal ver alertas (apt, Docker, systemd tocando rutas vigiladas): al terminar, ejecuta el test y revisa las alertas que NO provocaste; añade el proceso legítimo a la lista `sd_*` correspondiente en vez de borrar la regla.
