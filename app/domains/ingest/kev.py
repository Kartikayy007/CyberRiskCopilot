import json
import os
import pandas as pd
import requests
from app.core import state
from app.core.config import settings


def fetch_kev_catalog(force_refresh: bool = False) -> pd.DataFrame:
    os.makedirs(settings.kev_cache_dir, exist_ok=True)
    path = settings.kev_cache_path
    if force_refresh or not os.path.exists(path):
        resp = requests.get(settings.kev_url, timeout=30)
        resp.raise_for_status()
        with open(path, "w") as f:
            f.write(resp.text)
    with open(path) as f:
        payload = json.load(f)
    df = pd.DataFrame(payload["vulnerabilities"])
    state.DATA["kev"] = df
    return df
