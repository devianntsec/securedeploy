def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"


def test_get_cve_ok_and_normalized(client, upstream):
    r = client.get("/cves/CVE-2021-44228")
    assert r.status_code == 200
    body = r.json()
    assert body["id"] == "CVE-2021-44228"
    assert body["cvss_score"] == 10.0
    assert body["severity"] == "CRITICAL"
    assert body["cwes"] == ["CWE-502", "CWE-917"]
    assert body["description"].startswith("Apache Log4j2")
    assert upstream.requests[0].headers["apiKey"] == "test-key"


def test_get_cve_is_cached(client, upstream):
    client.get("/cves/CVE-2021-44228")
    client.get("/cves/CVE-2021-44228")
    assert len(upstream.requests) == 1


def test_lowercase_id_is_rejected_by_pattern_or_normalized(client):
    r = client.get("/cves/cve-2021-44228")
    assert r.status_code in (200, 422)


def test_invalid_id_rejected(client, upstream):
    r = client.get("/cves/not-a-cve")
    assert r.status_code == 422
    assert upstream.requests == []


def test_not_found(client, upstream):
    upstream.payload = {"vulnerabilities": [], "totalResults": 0}
    r = client.get("/cves/CVE-1999-0001")
    assert r.status_code == 404


def test_upstream_rate_limited_maps_to_503(client, upstream):
    upstream.status = 429
    r = client.get("/cves/CVE-2021-44228")
    assert r.status_code == 503


def test_upstream_error_maps_to_502(client, upstream):
    upstream.status = 500
    r = client.get("/cves/CVE-2021-44228")
    assert r.status_code == 502


def test_search_with_severity(client, upstream):
    r = client.get("/cves", params={"keyword": "log4j", "severity": "CRITICAL", "limit": 5})
    assert r.status_code == 200
    assert r.json()["returned"] == 1
    q = upstream.requests[0].url.params
    assert q["keywordSearch"] == "log4j"
    assert q["cvssV3Severity"] == "CRITICAL"
    assert q["resultsPerPage"] == "5"


def test_search_validation(client):
    assert client.get("/cves", params={"keyword": "x"}).status_code == 422
    assert client.get("/cves", params={"keyword": "log4j", "limit": 500}).status_code == 422
    assert client.get("/cves", params={"keyword": "log4j", "severity": "NOPE"}).status_code == 422
    assert client.get("/cves", params={"keyword": "a;rm -rf /"}).status_code == 422
