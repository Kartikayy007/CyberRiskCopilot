"""
CISA Known Exploited Vulnerabilities (KEV) catalog fetch + cross-reference.
Downloaded once on ingest and cached to disk; not committed to git.
"""

import os
import json
import requests
import pandas as pd

from app import state

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_CACHE_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "kev")
KEV_CACHE_PATH = os.path.join(KEV_CACHE_DIR, "kev_catalog.json")


def fetch_kev_catalog(force_refresh: bool = False) -> pd.DataFrame:
    os.makedirs(KEV_CACHE_DIR, exist_ok=True)

    if force_refresh or not os.path.exists(KEV_CACHE_PATH):
        resp = requests.get(KEV_URL, timeout=30)
        resp.raise_for_status()
        with open(KEV_CACHE_PATH, "w") as f:
            f.write(resp.text)

    with open(KEV_CACHE_PATH) as f:
        payload = json.load(f)

    df = pd.DataFrame(payload["vulnerabilities"])
    state.DATA["kev"] = df
    return df


def match_cve_against_kev(cve: str) -> dict | None:
    """Return the KEV row for a CVE, or None if not KEV-listed (not a guarantee it's safe — see README caveat)."""
    kev_df = state.DATA.get("kev")
    if kev_df is None or kev_df.empty:
        return None
    match = kev_df[kev_df["cveID"] == cve]
    if match.empty:
        return None
    return match.iloc[0].to_dict()
