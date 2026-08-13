from fastapi import APIRouter, Depends, Query
from app.endpoints import schemas
from app.core import state
from app.core.deps import require_structured
from app.core.sanitize import clean

router = APIRouter(dependencies=[Depends(require_structured)])


@router.get("/assets", responses={200: {"model": list[schemas.AssetRow]}})
def get_assets(exposed: bool | None = Query(None), criticality: str | None = Query(None)):
    df = state.DATA["assets"]
    if exposed is not None:
        df = df[df["internet_exposed"] == ("Yes" if exposed else "No")]
    if criticality:
        df = df[df["criticality"] == criticality]
    return clean(df.to_dict("records"))


@router.get("/vulnerabilities", responses={200: {"model": list[schemas.VulnerabilityRow]}})
def get_vulnerabilities(
    asset_id: str | None = Query(None), exploit_available: bool | None = Query(None)
):
    df = state.DATA["vulnerabilities"]
    if asset_id:
        df = df[df["asset_id"] == asset_id]
    if exploit_available is not None:
        df = df[df["exploit_available"] == ("Yes" if exploit_available else "No")]
    return clean(df.to_dict("records"))


@router.get("/threat-intel", responses={200: {"model": list[schemas.ThreatIntelRow]}})
def get_threat_intel(cve: str | None = Query(None)):
    df = state.DATA["threat_intelligence"]
    if cve:
        df = df[df["matched_cve_or_control"] == cve]
    return clean(df.to_dict("records"))
