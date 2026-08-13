import re

_SECTION_RE = re.compile(r"^###\s+\d+\.\s+(.+?)\s+[—-]\s+[\"“](.+?)[\"”]\s*$")
_FIELD_RE = re.compile(r"^\*\*(.+?):\*\*\s*(.*)$")

_FIELD_KEYS = {
    "target profile": "target_profile",
    "exploit chain": "exploit_chain",
    "ransomware": "ransomware",
    "confidence": "confidence",
    "iocs": "iocs",
}


def normalize_campaign(name) -> str:
    if not isinstance(name, str):
        return ""
    return name.strip().strip("\"“”").casefold()


def parse_campaigns(markdown: str) -> dict:
    campaigns: dict[str, dict] = {}
    current: dict | None = None

    for raw in markdown.split("\n"):
        line = raw.strip()

        header = _SECTION_RE.match(line)
        if header:
            actor, campaign = header.group(1).strip(), header.group(2).strip()
            current = {
                "threat_actor": actor,
                "campaign_name": campaign,
                "target_profile": None,
                "exploit_chain": None,
                "ransomware": None,
                "confidence": None,
                "iocs": None,
                "narrative": [],
            }
            campaigns[normalize_campaign(campaign)] = current
            continue

        if current is None:
            continue

        if line.startswith("---") or line.startswith("## "):
            current = None
            continue

        field = _FIELD_RE.match(line)
        if field:
            key = _FIELD_KEYS.get(field.group(1).strip().casefold())
            if key:
                current[key] = field.group(2).strip()
            continue

        if line:
            current["narrative"].append(line)

    for c in campaigns.values():
        c["narrative"] = " ".join(c["narrative"]).strip() or None

    return campaigns


def lookup(campaigns: dict, campaign_name) -> dict | None:
    if not campaigns:
        return None
    return campaigns.get(normalize_campaign(campaign_name))
