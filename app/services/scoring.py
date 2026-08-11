"""
Composite risk scoring. Joins vulnerabilities -> assets -> business_services
-> threat_intelligence -> KEV, and produces a weighted score per vulnerability.

Weights are a starting point, not tuned against ground truth (there isn't one
for this dataset) — see README "where it goes wrong" for the caveat on this.
"""

import pandas as pd

from app import state
from app.services.kev import match_cve_against_kev

CRITICALITY_WEIGHT = {"Critical": 1.0, "High": 0.75, "Medium": 0.5, "Low": 0.25}

WEIGHTS = {
    "cvss": 0.20,
    "exposure": 0.20,
    "exploit_or_kev": 0.20,
    "campaign_match": 0.25,
    "business_criticality": 0.10,
    "control_gap": 0.05,
}


def _find_threat_intel_matches(cve: str) -> pd.DataFrame:
    intel = state.DATA["threat_intelligence"]
    return intel[intel["matched_cve_or_control"] == cve]


def compute_scores() -> pd.DataFrame:
    vulns = state.DATA["vulnerabilities"]
    assets = state.DATA["assets"]
    services = state.DATA["business_services"]

    df = vulns.merge(assets, on="asset_id", how="left")
    df = df.merge(services, on="business_service", how="left")

    rows = []
    for _, row in df.iterrows():
        cve = row.get("cve")
        kev_hit = match_cve_against_kev(cve) if isinstance(cve, str) else None
        intel_matches = _find_threat_intel_matches(cve) if isinstance(cve, str) else pd.DataFrame()

        cvss_component = (row.get("cvss") or 0) / 10.0

        exposure_component = 1.0 if (
            row.get("asset_exposure") == "Internet" or row.get("internet_exposed") == "Yes"
        ) else 0.0

        exploit_or_kev_component = 0.0
        if row.get("exploit_available") == "Yes":
            exploit_or_kev_component += 0.5
        if kev_hit:
            exploit_or_kev_component += 0.5
        exploit_or_kev_component = min(exploit_or_kev_component, 1.0)

        campaign_component = 0.0
        if not intel_matches.empty:
            campaign_component = 1.0 if (intel_matches["ransomware_association"] == "Yes").any() else 0.6

        criticality_component = CRITICALITY_WEIGHT.get(row.get("criticality"), 0.25)

        control_gap_component = 0.0
        if row.get("edr_installed") == "No":
            control_gap_component += 0.5
        if row.get("patch_available") == "No":
            control_gap_component += 0.5
        control_gap_component = min(control_gap_component, 1.0)

        score = (
            cvss_component * WEIGHTS["cvss"]
            + exposure_component * WEIGHTS["exposure"]
            + exploit_or_kev_component * WEIGHTS["exploit_or_kev"]
            + campaign_component * WEIGHTS["campaign_match"]
            + criticality_component * WEIGHTS["business_criticality"]
            + control_gap_component * WEIGHTS["control_gap"]
        )

        rows.append({
            "vuln_id": row.get("vuln_id"),
            "asset_id": row.get("asset_id"),
            "asset_name": row.get("asset_name"),
            "cve": cve,
            "vulnerability_name": row.get("vulnerability_name"),
            "business_service": row.get("business_service"),
            "criticality": row.get("criticality"),
            "score": round(score, 4),
            "kev_matched": bool(kev_hit),
            "ransomware_campaign_matched": not intel_matches.empty and (intel_matches["ransomware_association"] == "Yes").any(),
            "threat_intel_matches": intel_matches.to_dict("records"),
        })

    result = pd.DataFrame(rows).sort_values("score", ascending=False).reset_index(drop=True)
    return result


def top_n_risks(n: int = 5) -> pd.DataFrame:
    return compute_scores().head(n)
