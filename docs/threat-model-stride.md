# Modelo de amenazas (STRIDE) — SecureDeploy

**Alcance:** API FastAPI que consulta la NVD, desplegada en una instancia EC2 (Docker) en AWS, con pipeline en GitHub Actions.
**Versión:** 0.1 · **Método:** STRIDE por elemento sobre el DFD · **Revisión:** cada cambio de arquitectura o trimestral.

## 1. Activos

| ID | Activo | Por qué importa |
|----|--------|-----------------|
| A1 | API key de la NVD (Secrets Manager) | Su abuso agota la cuota y compromete la reputación |
| A2 | Instancia EC2 y su rol IAM | Punto de apoyo hacia el resto de la cuenta |
| A3 | Imágenes en ECR | Una imagen alterada = ejecución de código en producción |
| A4 | Pipeline y rol OIDC de GitHub Actions | Quien lo controla despliega a producción |
| A5 | Integridad de las respuestas de la API | Los consumidores deciden en base a datos de vulnerabilidades |

## 2. Diagrama de flujo de datos

```
 Cliente ──HTTP:8000──▶ [Contenedor API] ──HTTPS──▶ NVD API
   (TB1)                    │   ▲ (TB3)
                            │   └─ env (tmpfs) ◀── [Host: script de arranque] ──IAM──▶ Secrets Manager
                            │                                   (TB2)
 Dev ──push──▶ GitHub ──OIDC──▶ AWS (ECR push, SSM SendCommand) ──▶ [Host]
   (TB4)         (TB5)
```
Fronteras de confianza: **TB1** Internet→API · **TB2** Host→AWS APIs · **TB3** API→NVD (tercero) · **TB4** Desarrollador→repositorio · **TB5** GitHub→AWS.

## 3. Amenazas y controles

| # | Cat. | Amenaza | Activo | Control implementado (dónde) | Riesgo residual |
|---|------|---------|--------|------------------------------|-----------------|
| T1 | **S** | Suplantación del despliegue: alguien usa credenciales AWS robadas de CI | A4 | OIDC sin claves de larga duración; trust policy restringida a `repo:<owner>/<repo>:ref:refs/heads/main` (`terraform/iam.tf`) | Bajo: compromiso de la cuenta de GitHub o de `main` |
| T2 | **S** | Suplantación de la NVD (MITM) | A5 | TLS con verificación activa; regla Semgrep que prohíbe `verify=False` (`.semgrep/securedeploy.yml`) | Bajo |
| T3 | **T** | Imagen manipulada o sobrescrita en ECR | A3 | Tags **inmutables**, scan on push, cifrado KMS, push solo desde rol OIDC (`terraform/ecr.tf`) | Medio: sin firma de imágenes (cosign) |
| T4 | **T** | Dependencia o imagen base vulnerable/maliciosa | A2,A3 | `pip-audit`, Trivy fs+imagen como gates, Dependabot, versiones fijadas (`ci.yml`, `requirements.txt`) | Medio: ataques de typosquatting no detectados por CVE |
| T5 | **T** | Modificación del host tras un compromiso | A2 | auditd (`detection/auditd`), Falco (`detection/falco`), contenedor read-only | Medio |
| T6 | **R** | Repudio: no se puede reconstruir quién hizo qué | A2,A4 | auditd con claves por evento, CloudTrail de la cuenta, VPC Flow Logs 365 d, deploy atribuible a SHA | Bajo: habilitar CloudTrail multi-región es prerrequisito de la cuenta |
| T7 | **I** | Fuga de la API key vía logs, imagen o repositorio | A1 | Secreto solo en Secrets Manager (KMS); nunca en Terraform state (valor cargado por CLI); `.gitignore`; Trivy `secret`; regla Semgrep contra log de claves; el código solo loguea "configurada/no" | Bajo |
| T8 | **I** | SSRF/RCE en la API roba credenciales del rol vía IMDS | A2 | IMDSv2 obligatorio + hop limit 1: el contenedor **no** alcanza el IMDS; el secreto llega por env, no por credenciales (`terraform/ec2.tf`) | Bajo. Trade-off: la clave es visible en `docker inspect` para quien ya es root |
| T9 | **I** | Cabeceras/errores que filtran información | A5 | `--no-server-header`, cabeceras de seguridad, errores genéricos de upstream (`app/main.py`) | Bajo |
| T10 | **D** | Agotar la cuota de la NVD con peticiones masivas | A1,A5 | Caché TTL, validación estricta de entrada, límite de resultados, cuotas del contenedor | **Medio**: no hay rate limiting por cliente (pendiente: WAF/API Gateway) |
| T11 | **D** | Saturar la instancia (CPU/memoria/procesos) | A2 | `--memory 256m --cpus 0.5 --pids-limit 128`, SG restringido a CIDRs autorizados | Medio |
| T12 | **E** | Escape de contenedor → root en el host | A2 | Usuario no-root (uid 10001), `--cap-drop ALL`, `no-new-privileges`, filesystem read-only, sin socket Docker, sysctl endurecido | Medio: kernel compartido |
| T13 | **E** | Rol de la instancia demasiado amplio | A1,A2 | Una sola acción de Secrets Manager sobre un solo ARN, `kms:Decrypt` condicionado a `ViaService`, ECR pull sobre un solo repo (`iam.tf`) | Bajo |
| T14 | **E** | Pipeline comprometido (acción de terceros manipulada) | A4 | Permisos mínimos por job, `id-token: write` solo en deploy, deploy solo desde `main` y tras todos los gates | **Medio**: acciones fijadas por tag, no por SHA (pendiente) |
| T15 | **S/E** | Fuerza bruta o robo de clave SSH | A2 | Solo clave pública, `AllowUsers`, fail2ban, SSH cerrado por defecto (acceso por SSM), CIDR de admin | Bajo |

## 4. Supuestos y fuera de alcance
- La seguridad de la cuenta AWS (MFA en root, CloudTrail, GuardDuty) se asume como baseline.
- No se modela la NVD como adversario (solo su indisponibilidad o respuestas malformadas).
- No hay datos personales ni autenticación de usuarios en esta versión.

## 5. Backlog de mitigaciones (ordenado por riesgo residual)
1. Rate limiting por cliente (WAF o API Gateway) — T10, T11.
2. Fijar las GitHub Actions por SHA + firma de imágenes con cosign y verificación en el host — T3, T14.
3. Autenticación (API key propia o JWT) en la API — T10.
4. GuardDuty + alertas de Falco hacia SNS/Telegram — T5, T12.
