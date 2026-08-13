import threading
from enum import Enum


class IngestStatus(str, Enum):
    IDLE = "idle"
    RUNNING = "running"
    READY = "ready"
    FAILED = "failed"


DATA = {
    "assets": None,
    "vulnerabilities": None,
    "threat_intelligence": None,
    "business_services": None,
    "remediation_guidance": None,
    "threat_report": None,
    "threat_report_campaigns": None,
    "kev": None,
}
NIST_COLLECTION = None
STATUS = IngestStatus.IDLE
STATUS_DETAIL: dict = {"stage": None, "degraded": [], "error": None}
DATA_VERSION = 0
LOCK = threading.Lock()


def structured_ready() -> bool:
    return DATA["assets"] is not None
