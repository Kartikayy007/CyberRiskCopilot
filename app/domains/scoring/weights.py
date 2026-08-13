CRITICALITY_WEIGHT = {"Critical": 1.0, "High": 0.75, "Medium": 0.5, "Low": 0.25}
WEIGHTS = {
    "cvss": 0.17,
    "exposure": 0.17,
    "exploit_or_kev": 0.17,
    "active_campaign": 0.18,
    "kev_ransomware": 0.06,
    "business_impact": 0.14,
    "missing_control": 0.04,
    "patch_blocked": 0.02,
    "aging": 0.05,
}
EDR_APPLICABLE_ASSET_TYPES = {
    "API Server",
    "Application Server",
    "Build Server",
    "Database",
    "Endpoint",
    "Kubernetes Cluster",
    "Mail Server",
    "Web Application",
    "Web Server",
}
ACTIVE_CAMPAIGN_RANSOMWARE = 1.0
ACTIVE_CAMPAIGN_NON_RANSOMWARE = 0.6
AGING_SATURATION_DAYS = 180
BUSINESS_IMPACT_MIX = {"severity": 0.6, "rto": 0.25, "compliance": 0.15}
RTO_URGENCY = ((1, 1.0), (4, 0.8), (12, 0.5), (24, 0.25))
RTO_URGENCY_FLOOR = 0.1
MULTI_ASSET_BUMP_PER_ASSET = 0.02
MULTI_ASSET_BUMP_CAP = 0.06
CONFIDENCE_RANK = {"High": 3, "Medium": 2, "Low": 1}
RETRIEVAL_HIGH_CONFIDENCE_DISTANCE = 0.75
RETRIEVAL_LOW_CONFIDENCE_DISTANCE = 0.95
RELATED_CONTROL_MAX_DISTANCE = 0.9
