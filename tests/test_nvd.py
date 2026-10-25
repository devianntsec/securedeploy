from app.nvd import normalize


def test_normalize_prefers_newest_cvss_and_handles_missing():
    out = normalize({"id": "CVE-2099-0001", "descriptions": [], "metrics": {}})
    assert out.cvss_score is None and out.description == "" and out.cwes == []
    out = normalize(
        {
            "id": "CVE-2099-0002",
            "metrics": {
                "cvssMetricV2": [{"cvssData": {"baseScore": 5.0}, "baseSeverity": "MEDIUM"}],
                "cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}],
            },
        }
    )
    assert out.cvss_score == 9.8 and out.severity == "CRITICAL"
