import os
import pandas as pd
from app.core import state
from app.core.config import settings
from app.domains.ingest.threat_report import parse_campaigns

REQUIRED_COLUMNS = {
    "assets": {"asset_id", "asset_name", "asset_type", "business_service", "criticality"},
    "vulnerabilities": {"vuln_id", "asset_id", "cve", "cvss", "days_open"},
    "threat_intelligence": {"intel_id", "matched_cve_or_control", "ransomware_association"},
    "business_services": {"business_service", "revenue_impact", "rto_hours"},
    "remediation_guidance": {"finding_type", "recommended_action"},
}
PRIMARY_KEYS = {
    "assets": "asset_id",
    "vulnerabilities": "vuln_id",
    "threat_intelligence": "intel_id",
    "business_services": "business_service",
}


class DataQualityError(RuntimeError):
    pass


def _read_csv(directory: str, name: str) -> pd.DataFrame:
    return pd.read_csv(os.path.join(directory, f"{name}.csv"), encoding="utf-8")


def _validate(frames: dict) -> dict:
    problems = []
    for name, required in REQUIRED_COLUMNS.items():
        missing = required - set(frames[name].columns)
        if missing:
            problems.append(f"{name}.csv missing columns: {sorted(missing)}")
    if problems:
        raise DataQualityError("; ".join(problems))

    warnings = []
    for name, key in PRIMARY_KEYS.items():
        dupes = frames[name][key][frames[name][key].duplicated()].unique().tolist()
        if dupes:
            warnings.append(f"{name}.csv duplicate {key}: {dupes[:5]}")

    known_assets = set(frames["assets"]["asset_id"])
    orphan_assets = sorted(set(frames["vulnerabilities"]["asset_id"]) - known_assets)
    if orphan_assets:
        warnings.append(f"vulnerabilities reference unknown asset_id: {orphan_assets[:5]}")

    known_services = set(frames["business_services"]["business_service"])
    orphan_services = sorted(
        {s for s in frames["assets"]["business_service"] if isinstance(s, str)} - known_services
    )
    if orphan_services:
        warnings.append(f"assets reference unknown business_service: {orphan_services[:5]}")

    vuln_ids = set(frames["vulnerabilities"]["cve"])
    intel_keys = frames["threat_intelligence"]["matched_cve_or_control"]
    matched_rows = intel_keys[intel_keys.isin(vuln_ids)]
    reconciliation = {
        "intel_rows": int(len(intel_keys)),
        "intel_rows_matching_vulnerabilities": int(len(matched_rows)),
        "unique_matched_identifiers": int(matched_rows.nunique()),
        "unmatched_intel_rows": int(len(intel_keys) - len(matched_rows)),
    }
    return {"warnings": warnings, "reconciliation": reconciliation}


def load_csvs() -> dict:
    d = settings.dataset_dir
    frames = {name: _read_csv(d, name) for name in REQUIRED_COLUMNS}
    quality = _validate(frames)
    for name, frame in frames.items():
        state.DATA[name] = frame

    with open(os.path.join(d, "synthetic_threat_report.md"), encoding="utf-8") as f:
        report = f.read()
    campaigns = parse_campaigns(report)
    if not campaigns:
        raise DataQualityError(
            "synthetic_threat_report.md produced zero campaign sections - check the file encoding "
            "and that '### N. Actor - \"Campaign\"' headings are intact"
        )
    state.DATA["threat_report"] = report
    state.DATA["threat_report_campaigns"] = campaigns

    state.STATUS_DETAIL["data_quality"] = quality
    return {
        **{name: len(frame) for name, frame in frames.items()},
        "threat_report_campaigns": len(campaigns),
    }
