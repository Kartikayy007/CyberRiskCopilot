from app.core import state
from app.core.sanitize import clean, yes
from app.domains.scoring.weights import CONFIDENCE_RANK


def build_intel_lookup() -> dict:
    intel = state.DATA.get("threat_intelligence")
    if intel is None or intel.empty:
        return {}
    lookup: dict[str, list[dict]] = {}
    for record in intel.to_dict("records"):
        key = record.get("matched_cve_or_control")
        if isinstance(key, str):
            lookup.setdefault(key, []).append(record)
    return lookup


def shape_threat_intel(records: list[dict]) -> list[dict]:
    shaped = []
    seen = set()
    for r in records:
        intel_id = r.get("intel_id")
        if intel_id in seen:
            continue
        seen.add(intel_id)
        shaped.append(
            {
                "intel_id": intel_id,
                "threat_actor": r.get("threat_actor"),
                "campaign_name": r.get("campaign_name"),
                "exploit_maturity": r.get("exploit_maturity"),
                "confidence": r.get("confidence"),
                "ransomware_association": yes(r.get("ransomware_association")),
                "active_last_seen": r.get("active_last_seen"),
                "target_sector": r.get("target_sector"),
                "target_region": r.get("target_region"),
                "summary": r.get("summary"),
            }
        )
    shaped.sort(
        key=lambda x: (CONFIDENCE_RANK.get(x["confidence"], 0), str(x["active_last_seen"] or "")),
        reverse=True,
    )
    return clean(shaped)
