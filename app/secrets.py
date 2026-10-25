"""Resolución de la API key de la NVD.

Orden: SD_NVD_API_KEY (dev) -> AWS Secrets Manager (SD_NVD_SECRET_ID) -> sin clave.
Sin clave la NVD limita a ~5 req/30 s; con clave, ~50 req/30 s.
El secreto puede ser texto plano o JSON {"api_key": "..."}.
"""

import json
import logging
from functools import lru_cache

from .config import Settings

log = logging.getLogger("securedeploy.secrets")

PLACEHOLDER = "REPLACE_ME"


def parse_secret_string(raw: str) -> str | None:
    raw = raw.strip()
    if not raw or raw == PLACEHOLDER:
        return None
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return raw
    if isinstance(data, dict):
        value = data.get("api_key")
        return value if isinstance(value, str) and value and value != PLACEHOLDER else None
    return None


@lru_cache(maxsize=4)
def _fetch_from_secrets_manager(secret_id: str, region: str) -> str | None:
    import boto3  # import perezoso: no se necesita fuera de AWS
    from botocore.exceptions import BotoCoreError, ClientError

    try:
        client = boto3.client("secretsmanager", region_name=region)
        resp = client.get_secret_value(SecretId=secret_id)
    except (BotoCoreError, ClientError) as exc:
        # Nunca logueamos el valor; solo el tipo de error.
        log.error("Fallo en la consulta al gestor remoto: %s", type(exc).__name__)
        return None
    return parse_secret_string(resp.get("SecretString", ""))


def get_nvd_api_key(settings: Settings) -> str | None:
    if settings.nvd_api_key:
        return settings.nvd_api_key
    if settings.nvd_secret_id:
        return _fetch_from_secrets_manager(settings.nvd_secret_id, settings.aws_region)
    return None
