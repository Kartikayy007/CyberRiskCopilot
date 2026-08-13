from fastapi import APIRouter, Response
from app.endpoints.schemas import IngestSummary
from app.core import state
from app.domains.ingest import bootstrap

router = APIRouter()


@router.get("/health", response_model=IngestSummary)
def health():
    return bootstrap.summary()


@router.get("/ready", response_model=IngestSummary)
def ready(response: Response):
    if state.STATUS is not state.IngestStatus.READY:
        response.status_code = 503
        response.headers["Retry-After"] = "15"
    return bootstrap.summary()
