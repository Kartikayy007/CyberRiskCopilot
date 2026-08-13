from fastapi import APIRouter, Depends, HTTPException, Query
from app.core.deps import require_admin
from app.endpoints.schemas import IngestSummary
from app.core import state
from app.domains import pipeline
from app.domains.ingest import bootstrap

router = APIRouter()


@router.post("/ingest", response_model=IngestSummary, dependencies=[Depends(require_admin)])
def ingest(
    force_rebuild: bool = Query(False, description="Re-embed NIST 800-53 from scratch"),
    refresh_kev: bool = Query(False, description="Re-download the CISA KEV catalog"),
):
    if not state.LOCK.acquire(blocking=False):
        raise HTTPException(status_code=409, detail="An ingest is already running.")
    try:
        result = bootstrap.run_full_ingest(force_rebuild=force_rebuild, refresh_kev=refresh_kev)
        pipeline.invalidate()
        return result
    finally:
        state.LOCK.release()


@router.get("/ingest/status", response_model=IngestSummary)
def ingest_status():
    return bootstrap.summary()
