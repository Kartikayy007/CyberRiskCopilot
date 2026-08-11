import os
import pandas as pd

from app import state

DATASET_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "dataset")


def load_csvs():
    state.DATA["assets"] = pd.read_csv(os.path.join(DATASET_DIR, "assets.csv"))
    state.DATA["vulnerabilities"] = pd.read_csv(os.path.join(DATASET_DIR, "vulnerabilities.csv"))
    state.DATA["threat_intelligence"] = pd.read_csv(os.path.join(DATASET_DIR, "threat_intelligence.csv"))
    state.DATA["business_services"] = pd.read_csv(os.path.join(DATASET_DIR, "business_services.csv"))
    state.DATA["remediation_guidance"] = pd.read_csv(os.path.join(DATASET_DIR, "remediation_guidance.csv"))
    with open(os.path.join(DATASET_DIR, "synthetic_threat_report.md")) as f:
        state.DATA["threat_report"] = f.read()

    return {
        "assets": len(state.DATA["assets"]),
        "vulnerabilities": len(state.DATA["vulnerabilities"]),
        "threat_intelligence": len(state.DATA["threat_intelligence"]),
        "business_services": len(state.DATA["business_services"]),
        "remediation_guidance": len(state.DATA["remediation_guidance"]),
    }
