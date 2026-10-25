---
title: "SecureDeploy: de un CVE lookup a un despliegue en AWS con gates de seguridad"
date: 2026-10-24
draft: true
tags: [devsecops, aws, terraform, ansible, falco, trivy]
---

> **Borrador.** Reemplaza los campos `⟨…⟩` con los números reales de tu ejecución. No publiques cifras que no hayas medido.

## Qué construí
Una API FastAPI que consulta la NVD, desplegada en AWS con Terraform y endurecida con Ansible, con un pipeline que bloquea el merge si falla lint, tests, Bandit, Semgrep, pip-audit o Trivy.

## La métrica
Medí el hardening del host con Lynis **antes y después** de aplicar Ansible:

| Métrica | Antes | Después |
|---|---|---|
| Lynis hardening index | ⟨N⟩ | ⟨N⟩ |
| Warnings | ⟨N⟩ | ⟨N⟩ |
| Suggestions | ⟨N⟩ | ⟨N⟩ |

(`make audit-before && make harden && make audit-after && make metrics`)

Otras cifras reales para citar: cobertura de tests ⟨%⟩, hallazgos de Trivy en la primera corrida ⟨N⟩ → ⟨N⟩ tras corregir, tiempo del pipeline ⟨min⟩, cuántos issues halló Semgrep/Bandit al inicio.

## Decisiones de diseño que importan
1. **Secretos:** la clave de la NVD vive en Secrets Manager con KMS; Terraform crea el contenedor, no el valor, para que nunca toque el state.
2. **IMDSv2 + hop limit 1:** un SSRF en la API no puede robar el rol de la instancia.
3. **OIDC en lugar de claves en GitHub:** el deploy solo se asume desde `main`.
4. **Detección:** reglas de Falco y auditd versionadas junto al código.

## Qué encontré / qué rompió
⟨Cuenta un hallazgo real: una regla CIS que rompió Docker, un finding de Trivy, un falso positivo de Falco…⟩

## Modelo de amenazas y respuesta a incidentes
Resumen del STRIDE y del playbook, enlazando a `docs/`.

## Qué falta
Rate limiting por cliente, firma de imágenes con cosign, acciones fijadas por SHA.
