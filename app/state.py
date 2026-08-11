"""
In-memory app state. Holds loaded CSVs and the NIST vector collection
after /ingest runs. Simple module-level singleton — fine for a single-process
take-home deployment, not meant to scale beyond that.
"""

DATA = {
    "assets": None,
    "vulnerabilities": None,
    "threat_intelligence": None,
    "business_services": None,
    "remediation_guidance": None,
    "threat_report": None,
    "kev": None,
}

NIST_COLLECTION = None  # set by app.rag.nist_ingest.build_or_load_collection()

INGESTED = False
