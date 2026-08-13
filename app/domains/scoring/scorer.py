import re
import pandas as pd
from app.core import state
from app.core.sanitize import yes
from app.domains.scoring.intel import build_intel_lookup
from app.domains.scoring.weights import (
    AGING_SATURATION_DAYS,
    CAMPAIGN_MATCH_NON_RANSOMWARE,
    CAMPAIGN_MATCH_RANSOMWARE,
    BUSINESS_IMPACT_MIX,
    CRITICALITY_WEIGHT,
    EDR_APPLICABLE_ASSET_TYPES,
    KEV_MATCHED,
    KEV_NOT_MATCHED,
    KEV_UNAVAILABLE,
    RTO_URGENCY,
    RTO_URGENCY_FLOOR,
    WEIGHTS,
)

_REAL_CVE_RE = re.compile("^CVE-\\d{4}-\\d+$")


def _cvss_score(value) -> float:
    if value is None or pd.isna(value):
        return 0.0
    try:
        return min(max(float(value) / 10.0, 0.0), 1.0)
    except (TypeError, ValueError):
        return 0.0


def _kev_ransomware(kev_hit) -> bool:
    if kev_hit is None:
        return False
    return str(kev_hit.get("knownRansomwareCampaignUse", "")).strip().lower() == "known"


def _aging_score(days_open) -> float:
    try:
        days = float(days_open)
    except (TypeError, ValueError):
        return 0.0
    if days <= 0:
        return 0.0
    return min(days / AGING_SATURATION_DAYS, 1.0)


def _rto_urgency(rto_hours) -> float:
    try:
        hours = float(rto_hours)
    except (TypeError, ValueError):
        return RTO_URGENCY_FLOOR
    for threshold, value in RTO_URGENCY:
        if hours <= threshold:
            return value
    return RTO_URGENCY_FLOOR


def _business_impact_score(row) -> float:
    severity = max(
        CRITICALITY_WEIGHT.get(row.get("criticality"), 0.25),
        CRITICALITY_WEIGHT.get(row.get("revenue_impact"), 0.0),
    )
    scope = row.get("compliance_scope")
    in_scope = (
        1.0 if isinstance(scope, str) and scope.strip() and scope.strip().lower() != "nan" else 0.0
    )
    return min(
        severity * BUSINESS_IMPACT_MIX["severity"]
        + _rto_urgency(row.get("rto_hours")) * BUSINESS_IMPACT_MIX["rto"]
        + in_scope * BUSINESS_IMPACT_MIX["compliance"],
        1.0,
    )


def classify_identifier(identifier: str) -> str:
    if not isinstance(identifier, str):
        return "unknown"
    if identifier.startswith("CVE-SYN-"):
        return "synthetic_cve"
    if _REAL_CVE_RE.match(identifier):
        return "cve"
    return "control_finding"


def _build_kev_lookup() -> dict:
    kev_df = state.DATA.get("kev")
    if kev_df is None or kev_df.empty:
        return {}
    return {row["cveID"]: row for row in kev_df.to_dict("records")}


def _kev_available() -> bool:
    kev_df = state.DATA.get("kev")
    return kev_df is not None and not kev_df.empty


def _missing_applicable_control(row) -> float:
    if row.get("asset_type") not in EDR_APPLICABLE_ASSET_TYPES:
        return 0.0
    return 1.0 if str(row.get("edr_installed")).strip().lower() == "no" else 0.0


def compute_scores() -> pd.DataFrame:
    vulns = state.DATA["vulnerabilities"]
    assets = state.DATA["assets"]
    services = state.DATA["business_services"]
    df = vulns.merge(assets, on="asset_id", how="left")
    df = df.merge(services, on="business_service", how="left")
    kev_lookup = _build_kev_lookup()
    kev_available = _kev_available()
    intel_lookup = build_intel_lookup()
    rows = []
    for _, row in df.iterrows():
        identifier = row.get("cve")
        kev_hit = kev_lookup.get(identifier) if isinstance(identifier, str) else None
        intel_matches = intel_lookup.get(identifier, []) if isinstance(identifier, str) else []
        intel_ransomware = any((yes(m.get("ransomware_association")) for m in intel_matches))
        kev_ransomware = _kev_ransomware(kev_hit)
        kev_status = KEV_MATCHED if kev_hit else KEV_NOT_MATCHED if kev_available else KEV_UNAVAILABLE
        components = {
            "cvss": _cvss_score(row.get("cvss")),
            "exposure": (
                1.0
                if row.get("asset_exposure") == "Internet" or yes(row.get("internet_exposed"))
                else 0.0
            ),
            "exploit_or_kev": min(
                (0.5 if yes(row.get("exploit_available")) else 0.0) + (0.5 if kev_hit else 0.0), 1.0
            ),
            "campaign_match": (
                CAMPAIGN_MATCH_RANSOMWARE
                if intel_ransomware
                else CAMPAIGN_MATCH_NON_RANSOMWARE if intel_matches else 0.0
            ),
            "kev_ransomware_history": 1.0 if kev_ransomware else 0.0,
            "business_impact": _business_impact_score(row),
            "aging": _aging_score(row.get("days_open")),
            "control_gap": _missing_applicable_control(row),
            "patch_constraint": (
                1.0 if str(row.get("patch_available")).strip().lower() == "no" else 0.0
            ),
        }
        score = sum((components[k] * WEIGHTS[k] for k in WEIGHTS))
        asset_name = row.get("asset_name")
        if not isinstance(asset_name, str) or not asset_name:
            asset_name = row.get("asset_id")
        rows.append(
            {
                "vuln_id": row.get("vuln_id"),
                "asset_id": row.get("asset_id"),
                "asset_name": asset_name,
                "cve": identifier,
                "id_type": classify_identifier(identifier),
                "vulnerability_name": row.get("vulnerability_name"),
                "affected_component": row.get("affected_component"),
                "business_service": row.get("business_service"),
                "criticality": row.get("criticality"),
                "severity": row.get("severity"),
                "cvss": row.get("cvss"),
                "asset_exposure": row.get("asset_exposure"),
                "internet_exposed": row.get("internet_exposed"),
                "exploit_available": row.get("exploit_available"),
                "patch_available": row.get("patch_available"),
                "edr_installed": row.get("edr_installed"),
                "days_open": row.get("days_open"),
                "score": round(score, 4),
                "component_scores": {k: round(v, 4) for k, v in components.items()},
                "asset_type": row.get("asset_type"),
                "kev_matched": bool(kev_hit),
                "kev_status": kev_status,
                "kev_ransomware_use": kev_ransomware,
                "kev_required_action": (kev_hit or {}).get("requiredAction"),
                "kev_date_added": (kev_hit or {}).get("dateAdded"),
                "threat_intel_campaign_matched": bool(intel_matches),
                "ransomware_campaign_matched": intel_ransomware,
                "threat_intel_matches": intel_matches,
            }
        )
    return pd.DataFrame(rows).sort_values("score", ascending=False).reset_index(drop=True)
