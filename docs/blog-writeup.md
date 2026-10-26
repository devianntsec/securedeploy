---
title: "SecureDeploy: una API de CVEs con gates de seguridad, hardening medido y detección con Falco"
date: 2026-10-26
draft: true
tags: [devsecops, terraform, ansible, falco, trivy, lynis]
---

## Qué construí
Una API FastAPI que consulta la NVD (`/health`, `/cves/{id}`, `/cves?keyword=&severity=`), empaquetada en una imagen no-root, con un pipeline de seguridad en GitHub Actions, infraestructura como código para AWS (Terraform), hardening del host con Ansible y reglas de detección propias en Falco. Repositorio: `github.com/devianntsec/securedeploy`.

**Alcance honesto:** el pipeline, la imagen, las reglas de Falco y el hardening están ejecutados y medidos. Terraform está validado (`validate`, `fmt` y Trivy config) pero **todavía no aplicado en AWS**; el hardening y la detección los probé en una VM local con Ubuntu 22.04, no en una instancia EC2.

## La métrica
Medí el hardening con Lynis **antes y después** de aplicar los roles de Ansible (SSH, sysctl, UFW, fail2ban, auditd, Docker y Falco) en una VM Ubuntu 22.04:

| Métrica | Antes | Después |
|---|---|---|
| Lynis hardening index | 63 | 77 |
| Warnings | 1 | 0 |
| Suggestions | 48 | 35 |

Reproducible con `make audit-before && make harden && make audit-after && make metrics`.

## Los gates del pipeline
Cada push ejecuta siete jobs: Ruff y Hadolint, tests (17, cobertura 97,5 %, piso de 85 %), Bandit, Semgrep con reglas públicas y propias, pip-audit, Trivy sobre el repositorio, la imagen y el IaC, y ansible-lint. Los jobs duran entre 20 s y 1 min.

Resultados medidos:
- Trivy sobre la imagen (Debian 13.7 y 26 paquetes Python): 0 vulnerabilidades HIGH/CRITICAL.
- Trivy sobre Terraform: 0 hallazgos, con 3 excepciones documentadas en el código (egress abierto para ECR, apt y NTP).
- Bandit: 0. Semgrep: 2 hallazgos en la primera corrida, ambos falsos positivos (la regla de fuga de credenciales en logs saltaba por el texto del mensaje, no por un secreto); reformulé los mensajes y quedó en 0.

## Decisiones de diseño que importan
1. **Secretos:** la clave de la NVD se lee de Secrets Manager con KMS; Terraform crea el contenedor del secreto, no su valor, para que nunca pase por el state.
2. **IMDSv2 con hop limit 1:** un SSRF en la API no puede alcanzar el rol de la instancia.
3. **OIDC en lugar de claves en GitHub:** el rol de despliegue solo se asume desde `main`.
4. **Contenedor mínimo:** usuario 10001, `--read-only`, `/tmp` sin exec, `--cap-drop ALL` y `no-new-privileges`. Verificado en ejecución.
5. **Detección versionada junto al código:** 26 reglas de Falco con IDs estables, y un script (`scripts/test_falco.sh`) que dispara cada una de forma segura.

## Detección: 26 reglas, 26 probadas en ejecución
Las reglas cubren el contenedor (shell, procesos fuera de allowlist, egreso, acceso a IMDS, escrituras), el host (identidad, persistencia, módulos de kernel, manipulación de Falco/auditd, logs) y señales mixtas (ejecución desde `/tmp`, reverse shell). En la VM, el script las dispara y las 26 generaron su alerta. Con el sistema en reposo durante 180 s, con el healthcheck del contenedor activo, el número de alertas fue **cero**.

## Qué encontré / qué rompió
- **Falco solo dispara la primera regla que coincide.** Mi regla "herramienta de paquetes en el contenedor" no saltaba nunca: otra regla más general, definida antes, coincidía con el mismo evento. La solución fue `rule_matching: all`. Sin la prueba automatizada no lo habría visto.
- **`sshd` parecía un reverse shell.** Cada conexión SSH duplica el socket sobre stdin/stdout, que es justo la firma que busca la regla. Excluí el binario real por ruta.
- **1.600 alertas de ruido por una exclusión olvidada.** runc se reejecuta en cada `docker exec` y en cada healthcheck, y una de mis reglas no lo excluía. Medir el ruido en reposo, y no solo si las reglas disparan, fue lo que lo destapó.
- **El CI falló en 3 segundos.** El tag de `trivy-action` que usaba no existía (los tags llevan prefijo `v`). Aproveché para fijar la acción por SHA.
- **ansible-lint pasaba en mi máquina y fallaba en el CI**, porque en local el paquete `ansible` trae colecciones que el CI no instalaba. Además migré `apt_repository` (deprecado) a `deb822_repository`.

## Modelo de amenazas y respuesta a incidentes
STRIDE con 15 amenazas mapeadas a sus controles y un playbook de respuesta con 5 escenarios, ambos en `docs/`. Las reglas de Falco están referenciadas por ID desde el playbook.

## Qué falta
- Aplicar Terraform en AWS y probar el despliegue por OIDC, Secrets Manager y SSM.
- Rol CIS con su propio reporte y una segunda medición.
- Protección de rama para que el merge quede bloqueado por los gates.
- Rate limiting por cliente, firma de imágenes con cosign y fijar por SHA el resto de las acciones del workflow.
- Comprobar cómo interactúa UFW con los puertos que publica Docker.
