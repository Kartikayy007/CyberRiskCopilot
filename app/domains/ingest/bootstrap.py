import traceback
from app.core import state
from app.domains.ingest.csv_loader import load_csvs
from app.domains.ingest.kev import fetch_kev_catalog
from app.domains.rag.embedder import get_embedder
from app.domains.rag.store import build_or_load_collection


def load_structured() -> dict:
    counts = load_csvs()
    state.STATUS_DETAIL["csv_counts"] = counts
    return counts


def preload_embedder() -> None:
    get_embedder()


def load_heavy(force_rebuild: bool = False, refresh_kev: bool = False) -> dict:
    state.STATUS = state.IngestStatus.RUNNING
    state.STATUS_DETAIL["error"] = None
    state.STATUS_DETAIL["degraded"] = []
    state.STATUS_DETAIL["stage"] = "fetching_cisa_kev"
    try:
        kev_df = fetch_kev_catalog(force_refresh=refresh_kev)
        state.STATUS_DETAIL["kev_records"] = len(kev_df)
    except Exception as e:
        state.DATA["kev"] = None
        state.STATUS_DETAIL["kev_records"] = 0
        state.STATUS_DETAIL["degraded"].append("kev")
        state.STATUS_DETAIL["kev_error"] = str(e)
    state.STATUS_DETAIL["stage"] = "embedding_nist_800_53"
    try:
        collection = build_or_load_collection(force_rebuild=force_rebuild)
        state.NIST_COLLECTION = collection
        state.STATUS_DETAIL["nist_chunks"] = collection.count()
    except Exception as e:
        state.STATUS = state.IngestStatus.FAILED
        state.STATUS_DETAIL["stage"] = "failed"
        state.STATUS_DETAIL["error"] = f"{type(e).__name__}: {e}"
        state.STATUS_DETAIL["traceback"] = traceback.format_exc()
        raise
    state.DATA_VERSION += 1
    state.STATUS = state.IngestStatus.READY
    state.STATUS_DETAIL["stage"] = "ready"
    return summary()


def run_full_ingest(force_rebuild: bool = False, refresh_kev: bool = False) -> dict:
    load_structured()
    return load_heavy(force_rebuild=force_rebuild, refresh_kev=refresh_kev)


def summary() -> dict:
    return {
        "status": state.STATUS.value,
        "data_version": state.DATA_VERSION,
        "csv_counts": state.STATUS_DETAIL.get("csv_counts"),
        "kev_records": state.STATUS_DETAIL.get("kev_records"),
        "nist_chunks": state.STATUS_DETAIL.get("nist_chunks"),
        "stage": state.STATUS_DETAIL.get("stage"),
        "degraded": state.STATUS_DETAIL.get("degraded", []),
        "error": state.STATUS_DETAIL.get("error"),
    }
