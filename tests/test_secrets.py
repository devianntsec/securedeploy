from unittest.mock import MagicMock, patch

from app.config import Settings
from app.secrets import _fetch_from_secrets_manager, get_nvd_api_key, parse_secret_string


def test_parse_plain_and_json():
    assert parse_secret_string("abc") == "abc"
    assert parse_secret_string('{"api_key": "xyz"}') == "xyz"


def test_parse_placeholder_and_empty():
    assert parse_secret_string("REPLACE_ME") is None
    assert parse_secret_string('{"api_key": "REPLACE_ME"}') is None
    assert parse_secret_string("") is None
    assert parse_secret_string("[1, 2]") is None


def test_env_key_has_priority():
    s = Settings(nvd_api_key="direct", nvd_secret_id="arn:x")
    assert get_nvd_api_key(s) == "direct"


def test_no_sources_returns_none():
    assert get_nvd_api_key(Settings()) is None


def test_secrets_manager_path():
    _fetch_from_secrets_manager.cache_clear()
    fake = MagicMock()
    fake.get_secret_value.return_value = {"SecretString": '{"api_key": "from-sm"}'}
    with patch("boto3.client", return_value=fake) as mk:
        s = Settings(nvd_secret_id="securedeploy/nvd-api-key", aws_region="us-east-1")
        assert get_nvd_api_key(s) == "from-sm"
        mk.assert_called_once_with("secretsmanager", region_name="us-east-1")
    _fetch_from_secrets_manager.cache_clear()


def test_secrets_manager_failure_degrades_gracefully():
    from botocore.exceptions import ClientError

    _fetch_from_secrets_manager.cache_clear()
    fake = MagicMock()
    fake.get_secret_value.side_effect = ClientError({"Error": {"Code": "AccessDenied"}}, "GetSecretValue")
    with patch("boto3.client", return_value=fake):
        assert get_nvd_api_key(Settings(nvd_secret_id="x")) is None
    _fetch_from_secrets_manager.cache_clear()
