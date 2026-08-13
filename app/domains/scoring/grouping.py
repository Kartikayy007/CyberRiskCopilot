from app.core import state
from app.core.sanitize import clean, yes
from app.domains.ingest.threat_report import lookup as lookup_campaign
from app.domains.scoring.intel import build_intel_lookup, shape_threat_intel
from app.domains.scoring.scorer import compute_scores
from app.domains.scoring.weights import (
    CRITICALITY_WEIGHT,
    MULTI_ASSET_BUMP_CAP,
    MULTI_ASSET_BUMP_PER_ASSET,
)


def _max_criticality(values) -> str | None:
    ranked = [v for v in values if v in CRITICALITY_WEIGHT]
    if not ranked:
        return None
    return max(ranked, key=lambda v: CRITICALITY_WEIGHT[v])


def _campaign_detail(intel: list[dict]) -> dict | None:
    campaigns = state.DATA.get("threat_report_campaigns") or {}
    for t in intel:
        detail = lookup_campaign(campaigns, t.get("campaign_name"))
        if detail:
            return detail
    return None


def compute_grouped_scores() -> list[dict]:
    scored = compute_scores()
    intel_lookup = build_intel_lookup()
    groups = []
    for identifier, chunk in scored.groupby("cve", dropna=False, sort=False):
        chunk = chunk.sort_values(["score", "vuln_id"], ascending=[False, True])
        rows = chunk.to_dict("records")
        canonical = rows[0]
        intel = shape_threat_intel(intel_lookup.get(identifier, []))
        affected_assets = [
            {
                "asset_id": r["asset_id"],
                "asset_name": r["asset_name"],
                "vuln_id": r["vuln_id"],
                "vulnerability_name": r["vulnerability_name"],
                "business_service": r["business_service"],
                "criticality": r["criticality"],
                "asset_exposure": r["asset_exposure"],
                "internet_exposed": r["internet_exposed"],
                "edr_installed": r["edr_installed"],
                "days_open": r["days_open"],
                "score": r["score"],
            }
            for r in rows
        ]
        max_score = float(chunk["score"].max())
        bump = min(MULTI_ASSET_BUMP_PER_ASSET * (len(rows) - 1), MULTI_ASSET_BUMP_CAP)
        score = max_score + (1.0 - max_score) * bump
        names = list(dict.fromkeys((r["vulnerability_name"] for r in rows)))
        services = sorted(
            {r["business_service"] for r in rows if isinstance(r["business_service"], str)}
        )
        groups.append(
            {
                "risk_id": identifier,
                "id_type": canonical["id_type"],
                "vulnerability_name": canonical["vulnerability_name"],
                "alias_names": names[1:],
                "score": round(score, 4),
                "max_asset_score": round(max_score, 4),
                "cvss": float(chunk["cvss"].max()) if chunk["cvss"].notna().any() else None,
                "severity": canonical["severity"],
                "affected_component": canonical["affected_component"],
                "patch_available": canonical["patch_available"],
                "asset_count": len(rows),
                "internet_exposed_asset_count": sum(
                    (
                        1
                        for r in rows
                        if r["asset_exposure"] == "Internet" or yes(r["internet_exposed"])
                    )
                ),
                "affected_assets": affected_assets,
                "business_services": services,
                "max_criticality": _max_criticality((r["criticality"] for r in rows)),
                "kev_matched": bool(chunk["kev_matched"].any()),
                "kev_status": (
                    "yes"
                    if chunk["kev_matched"].any()
                    else "unknown" if (chunk["kev_status"] == "unknown").any() else "no"
                ),
                "kev_ransomware_use": bool(chunk["kev_ransomware_use"].any()),
                "kev_required_action": next(
                    (x for x in chunk["kev_required_action"] if isinstance(x, str) and x.strip()),
                    None,
                ),
                "kev_date_added": next(
                    (x for x in chunk["kev_date_added"] if isinstance(x, str) and x.strip()), None
                ),
                "active_campaign_matched": bool(chunk["active_campaign_matched"].any()),
                "active_ransomware_campaign": bool(chunk["active_ransomware_campaign"].any()),
                "threat_intel": intel,
                "campaign_detail": _campaign_detail(intel),
                "component_scores": canonical["component_scores"],
                "vuln_ids": [r["vuln_id"] for r in rows],
            }
        )
    groups.sort(key=lambda g: g["score"], reverse=True)
    return clean(groups)
