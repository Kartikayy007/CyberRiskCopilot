import secrets
from fastapi import Header, HTTPException, Query
from app.core import state
from app.core.config import settings


def require_admin(x_admin_token: str | None = Header(default=None)) -> None:
    expected = settings.admin_token()
    if not expected:
        return
    if not x_admin_token or not secrets.compare_digest(x_admin_token, expected):
        raise HTTPException(status_code=401, detail="Missing or invalid X-Admin-Token.")


def require_admin_for_nocache(
    nocache: bool = Query(False), x_admin_token: str | None = Header(default=None)
) -> None:
    if nocache:
        require_admin(x_admin_token)


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
