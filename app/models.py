from enum import StrEnum

from pydantic import BaseModel


class Severity(StrEnum):
    low = "LOW"
    medium = "MEDIUM"
    high = "HIGH"
    critical = "CRITICAL"


class CVE(BaseModel):
    id: str
    published: str | None = None
    last_modified: str | None = None
    description: str = ""
    cvss_score: float | None = None
    severity: str | None = None
    vector: str | None = None
    cwes: list[str] = []
    references: list[str] = []


class CVEList(BaseModel):
    total_results: int
    returned: int
    items: list[CVE]
