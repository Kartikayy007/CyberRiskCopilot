from fastapi import HTTPException
from app.core import state


def require_structured() -> None:
    if not state.structured_ready():
        raise HTTPException(status_code=503, detail="Data is still loading.")


def require_ready() -> None:
    if state.STATUS is state.IngestStatus.READY:
        return
    if state.STATUS is state.IngestStatus.FAILED:
        raise HTTPException(
            status_code=503,
            detail=f"Ingest failed: {state.STATUS_DETAIL.get('error')}",
            headers={"Retry-After": "30"},
        )
    raise HTTPException(
        status_code=503,
        detail=f"Warming up: {state.STATUS_DETAIL.get('stage') or 'starting'}. This runs once at startup.",
        headers={"Retry-After": "15"},
    )
