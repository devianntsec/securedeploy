"""Cliente asíncrono de la NVD API 2.0 con caché TTL en memoria."""

import time
from typing import Any

import httpx

from .config import Settings
from .models import CVE, CVEList

_CVSS_KEYS = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")


class CVENotFoundError(Exception):
    pass


class UpstreamError(Exception):
    def __init__(self, message: str, status_code: int = 502):
        super().__init__(message)
        self.status_code = status_code


def normalize(cve: dict[str, Any]) -> CVE:
    desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    score = severity = vector = None
    metrics = cve.get("metrics", {})
    for key in _CVSS_KEYS:
        if metrics.get(key):
            data = metrics[key][0].get("cvssData", {})
            score = data.get("baseScore")
            severity = data.get("baseSeverity") or metrics[key][0].get("baseSeverity")
            vector = data.get("vectorString")
            break
    cwes = sorted(
        {
            d["value"]
            for w in cve.get("weaknesses", [])
            for d in w.get("description", [])
            if d.get("value", "").startswith("CWE-")
        }
    )
    refs = [r["url"] for r in cve.get("references", [])][:10]
    return CVE(
        id=cve["id"],
        published=cve.get("published"),
        last_modified=cve.get("lastModified"),
        description=desc,
        cvss_score=score,
        severity=severity,
        vector=vector,
        cwes=cwes,
        references=refs,
    )


class NVDClient:
    def __init__(
        self,
        settings: Settings,
        api_key: str | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ):
        self._settings = settings
        headers = {"User-Agent": "securedeploy/0.1 (+https://blog.deviannt.com)"}
        if api_key:
            headers["apiKey"] = api_key
        self._http = httpx.AsyncClient(
            base_url=settings.nvd_base_url,
            headers=headers,
            timeout=settings.http_timeout_seconds,
            transport=transport,
        )
        self._cache: dict[str, tuple[float, Any]] = {}

    async def aclose(self) -> None:
        await self._http.aclose()

    def _cache_get(self, key: str) -> Any | None:
        hit = self._cache.get(key)
        if hit and hit[0] > time.monotonic():
            return hit[1]
        self._cache.pop(key, None)
        return None

    def _cache_put(self, key: str, value: Any) -> None:
        if len(self._cache) >= self._settings.cache_max_entries:
            self._cache.pop(next(iter(self._cache)))
        self._cache[key] = (time.monotonic() + self._settings.cache_ttl_seconds, value)

    async def _get(self, params: dict[str, Any]) -> dict[str, Any]:
        try:
            resp = await self._http.get("", params=params)
        except httpx.HTTPError as exc:
            raise UpstreamError(f"NVD inaccesible: {type(exc).__name__}", 502) from exc
        if resp.status_code in (403, 429):
            raise UpstreamError("NVD aplicó rate limiting o rechazó la clave", 503)
        if resp.status_code >= 400:
            raise UpstreamError(f"NVD respondió {resp.status_code}", 502)
        return resp.json()

    async def get_cve(self, cve_id: str) -> CVE:
        key = f"cve:{cve_id}"
        if (cached := self._cache_get(key)) is not None:
            return cached
        data = await self._get({"cveId": cve_id})
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            raise CVENotFoundError(cve_id)
        result = normalize(vulns[0]["cve"])
        self._cache_put(key, result)
        return result

    async def search(self, keyword: str, severity: str | None, limit: int) -> CVEList:
        key = f"search:{keyword.lower()}:{severity}:{limit}"
        if (cached := self._cache_get(key)) is not None:
            return cached
        params: dict[str, Any] = {"keywordSearch": keyword, "resultsPerPage": limit}
        if severity:
            params["cvssV3Severity"] = severity
        data = await self._get(params)
        items = [normalize(v["cve"]) for v in data.get("vulnerabilities", [])]
        result = CVEList(
            total_results=data.get("totalResults", len(items)),
            returned=len(items),
            items=items,
        )
        self._cache_put(key, result)
        return result
