import httpx
import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import app, get_client
from app.nvd import NVDClient

LOG4SHELL = {
    "id": "CVE-2021-44228",
    "published": "2021-12-10T10:15:09.143",
    "lastModified": "2024-06-27T19:15:00.000",
    "descriptions": [
        {"lang": "es", "value": "descripcion"},
        {
            "lang": "en",
            "value": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP.",
        },
    ],
    "metrics": {
        "cvssMetricV31": [
            {
                "cvssData": {
                    "baseScore": 10.0,
                    "baseSeverity": "CRITICAL",
                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                }
            }
        ]
    },
    "weaknesses": [{"description": [{"lang": "en", "value": "CWE-502"}, {"lang": "en", "value": "CWE-917"}]}],
    "references": [{"url": "https://logging.apache.org/log4j/2.x/security.html"}],
}


class Recorder:
    def __init__(self):
        self.requests: list[httpx.Request] = []
        self.status = 200
        self.payload: dict = {"vulnerabilities": [{"cve": LOG4SHELL}], "totalResults": 1}

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return httpx.Response(self.status, json=self.payload)


@pytest.fixture
def upstream() -> Recorder:
    return Recorder()


@pytest.fixture
def client(upstream: Recorder):
    nvd = NVDClient(Settings(), api_key="test-key", transport=httpx.MockTransport(upstream.handler))
    app.dependency_overrides[get_client] = lambda: nvd
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()
