# Playbook de respuesta a incidentes — SecureDeploy

Basado en NIST SP 800-61r2 (Preparación → Detección y análisis → Contención, erradicación, recuperación → Post-incidente).

## 0. Roles y canales
| Rol | Responsabilidad |
|-----|-----------------|
| Respondedor principal (owner del servicio) | Decide contención, ejecuta, documenta |
| Soporte | Revisión de pares / comunicación |
Canal: issue privado `incident-YYYYMMDD-NN` en el repositorio + línea de tiempo en UTC.

## 1. Fuentes de detección
| Fuente | Qué señala | Dónde mirar |
|--------|------------|-------------|
| Falco | Shell/escritura/conexión anómala en el contenedor | `jq -c 'select(.priority=="Critical")' /var/log/falco/events.json` |
| auditd | Cambios en identidad, sudoers, módulos de kernel, Docker | `ausearch -k <clave> -ts recent -i` |
| VPC Flow Logs | Exfiltración o escaneo | CloudWatch `/<project>/vpc-flow` |
| CloudTrail | Uso del rol de la instancia o del rol OIDC desde IP inesperada | Consola o Athena |
| Trivy / Dependabot | CVE nuevo en dependencias | Pestaña Security de GitHub |

## 2. Severidades
| Sev | Criterio | Objetivo de contención |
|-----|----------|------------------------|
| 1 | Ejecución de código en host/contenedor confirmada, o clave expuesta públicamente | 30 min |
| 2 | Indicador fuerte sin confirmar, CVE crítico explotable en producción | 4 h |
| 3 | Anomalía aislada, CVE no explotable | 3 días |

## 3. Escenarios

### E1 — Fuga de la API key de la NVD
1. **Contener:** solicitar una clave nueva en la NVD y revocar la anterior.
2. **Rotar:** `aws secretsmanager put-secret-value --secret-id <ARN> --secret-string '{"api_key":"NUEVA"}'`
3. **Aplicar:** `aws ssm send-command --instance-ids <ID> --document-name AWS-RunShellScript --parameters 'commands=["systemctl restart securedeploy"]'`
4. **Investigar:** `git log -S"<prefijo>" --all`, búsqueda en logs, CloudTrail `GetSecretValue` por identidades inesperadas.
5. **Post:** añadir regla Trivy/gitleaks si la fuga fue por repo.

### E2 — Alerta Falco SD-C01 "Shell dentro del contenedor" (Sev 1 hasta demostrar lo contrario)
1. **Preservar evidencia antes de tocar nada:**
   ```bash
   docker inspect securedeploy > /var/tmp/ir-inspect.json
   docker logs securedeploy > /var/tmp/ir-container.log 2>&1
   docker export securedeploy | gzip > /var/tmp/ir-container-fs.tar.gz
   ausearch -ts today -i > /var/tmp/ir-audit.txt
   ```
2. **Contener:** aislar la instancia cambiando su SG a uno sin ingreso ni egreso (`aws ec2 modify-instance-attribute --instance-id <ID> --groups <sg-aislado>`). No apagar: se pierde memoria volátil.
3. **Analizar:** procesos (`ps auxf`), conexiones (`ss -tupn`), imagen en uso vs tag esperado, `docker diff`, revisar si el rol IAM de la instancia fue usado desde fuera (CloudTrail).
4. **Erradicar:** NO reparar en sitio. Terminar la instancia y recrearla (`terraform apply -replace=aws_instance.app`), rotar la clave NVD (E1) y redeplegar un tag **previo y verificado**.
5. **Recuperar:** smoke test `/health`, vigilar Falco 24 h.
6. **Post:** causa raíz (¿vulnerabilidad de la app? ¿dependencia?) y nueva regla de detección.

### E3 — Dependencia o imagen comprometida (supply chain)
1. Identificar el paquete/versión (alerta de Dependabot/Trivy/aviso público).
2. Determinar exposición: `docker run --rm --entrypoint pip <imagen> freeze`.
3. Contener: congelar despliegues (desactivar `AWS_DEPLOY_ENABLED` en las variables del repositorio).
4. Corregir: fijar versión segura en `requirements.txt`, PR, esperar gates, desplegar.
5. Si la imagen en producción incluye el componente comprometido, tratar como E2 desde el paso 2.

### E4 — Fuerza bruta o acceso SSH no autorizado
1. `ausearch -k logins -i`, `journalctl -u ssh`, `fail2ban-client status sshd`.
2. Si hubo login exitoso desde IP desconocida: tratar como E2. Si solo intentos fallidos: reducir `admin_cidr` o cerrar SSH (SSM) y registrar.

### E5 — Credenciales del rol OIDC (CI) abusadas
1. Revisar CloudTrail por `AssumeRoleWithWebIdentity` con `sub` inesperado.
2. Contener: adjuntar política de denegación total al rol `…-github-actions` o eliminar la relación de confianza.
3. Revisar imágenes recientes en ECR (digest vs commits) y compararlas con las desplegadas.
4. Restaurar la confianza solo tras verificar la integridad de `main`.

## 4. Comunicación
- Sev 1/2: nota interna con hora de detección, alcance, acciones, estado. Si hay datos de terceros afectados, evaluar obligaciones legales de notificación aplicables.
- Sin datos personales en esta versión; el impacto principal es disponibilidad/integridad.

## 5. Post-incidente (máx. 5 días hábiles)
Plantilla: resumen · línea de tiempo UTC · causa raíz · qué funcionó/falló en detección · acciones correctivas con responsable y fecha · actualización de `threat-model-stride.md` y de las reglas en `detection/`.

## 6. Ejercicio de mesa (tabletop)
Ejecutar E2 y E1 cada 6 meses con una alerta simulada (`docker exec -it securedeploy sh` en un entorno de pruebas dispara la regla). Registrar tiempos de detección y contención como métrica.
