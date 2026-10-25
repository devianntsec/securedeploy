import logging
import re
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Path, Query, Request
from fastapi.responses import JSONResponse

from . import __version__
from .config import get_settings
from .models import CVE, CVEList, Severity
from .nvd import CVENotFoundError, NVDClient, UpstreamError
from .secrets import get_nvd_api_key

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("securedeploy")

CVE_ID_PATTERN = r"^CVE-\d{4}-\d{4,19}$"


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    api_key = get_nvd_api_key(settings)
    log.info("Cliente NVD iniciado (autenticado=%s)", bool(api_key))
    app.state.nvd = NVDClient(settings, api_key=api_key)
    yield
    await app.state.nvd.aclose()


app = FastAPI(
    title="SecureDeploy CVE API",
    version=__version__,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url=None,
)


def get_client(request: Request) -> NVDClient:
    return request.app.state.nvd


Client = Annotated[NVDClient, Depends(get_client)]


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    if request.url.path not in ("/docs", "/openapi.json"):
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    return response


@app.exception_handler(UpstreamError)
async def upstream_handler(_: Request, exc: UpstreamError) -> JSONResponse:
    log.warning("upstream error: %s", exc)
    return JSONResponse({"detail": str(exc)}, status_code=exc.status_code)


@app.get("/health", tags=["ops"])
async def health() -> dict[str, str]:
    return {"status": "ok", "version": __version__}


@app.get("/cves/{cve_id}", response_model=CVE, tags=["cves"])
async def get_cve(
    cve_id: Annotated[str, Path(pattern=CVE_ID_PATTERN, description="Ej.: CVE-2021-44228")],
    client: Client,
) -> CVE:
    try:
        return await client.get_cve(cve_id.upper())
    except CVENotFoundError:
        raise HTTPException(status_code=404, detail=f"{cve_id} no existe en la NVD") from None


@app.get("/cves", response_model=CVEList, tags=["cves"])
async def search_cves(
    client: Client,
    keyword: Annotated[str, Query(min_length=2, max_length=100)],
    severity: Severity | None = None,
    limit: Annotated[int, Query(ge=1, le=50)] = 10,
) -> CVEList:
    if not re.fullmatch(r"[\w .:/+\-]+", keyword):
        raise HTTPException(status_code=422, detail="keyword contiene caracteres no permitidos")
    limit = min(limit, get_settings().max_results)
    return await client.search(keyword, severity.value if severity else None, limit)
