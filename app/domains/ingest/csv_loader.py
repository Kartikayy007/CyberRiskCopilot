import os
import pandas as pd
from app.core import state
from app.core.config import settings
from app.domains.ingest.threat_report import parse_campaigns


def load_csvs() -> dict:
    d = settings.dataset_dir
    state.DATA["assets"] = pd.read_csv(os.path.join(d, "assets.csv"))
    state.DATA["vulnerabilities"] = pd.read_csv(os.path.join(d, "vulnerabilities.csv"))
    state.DATA["threat_intelligence"] = pd.read_csv(os.path.join(d, "threat_intelligence.csv"))
    state.DATA["business_services"] = pd.read_csv(os.path.join(d, "business_services.csv"))
    state.DATA["remediation_guidance"] = pd.read_csv(os.path.join(d, "remediation_guidance.csv"))
    with open(os.path.join(d, "synthetic_threat_report.md")) as f:
        report = f.read()
    state.DATA["threat_report"] = report
    state.DATA["threat_report_campaigns"] = parse_campaigns(report)
    return {
        "assets": len(state.DATA["assets"]),
        "vulnerabilities": len(state.DATA["vulnerabilities"]),
        "threat_intelligence": len(state.DATA["threat_intelligence"]),
        "business_services": len(state.DATA["business_services"]),
        "remediation_guidance": len(state.DATA["remediation_guidance"]),
        "threat_report_campaigns": len(state.DATA["threat_report_campaigns"]),
    }
