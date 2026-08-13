from pydantic import BaseModel, ConfigDict, Field


class IngestSummary(BaseModel):
    status: str
    data_version: int
    csv_counts: dict[str, int] | None = None
    kev_records: int | None = None
    nist_chunks: int | None = None
    stage: str | None = None
    degraded: list[str] = Field(default_factory=list)
    error: str | None = None


class NistHit(BaseModel):
    text: str
    control_id: str | None = None
    control_name: str | None = None
    page: int | None = None
    distance: float


class NistSearchResponse(BaseModel):
    query: str
    results: list[NistHit]


class _Row(BaseModel):
    model_config = ConfigDict(extra="allow")


class AssetRow(_Row):
    asset_id: str | None = None
    asset_name: str | None = None
    business_service: str | None = None
    criticality: str | None = None
    internet_exposed: str | None = None


class VulnerabilityRow(_Row):
    vuln_id: str | None = None
    asset_id: str | None = None
    cve: str | None = None
    severity: str | None = None
    cvss: float | None = None


class ThreatIntelRow(_Row):
    intel_id: str | None = None
    threat_actor: str | None = None
    campaign_name: str | None = None
    matched_cve_or_control: str | None = None


class ThreatIntelItem(BaseModel):
    intel_id: str | None = None
    threat_actor: str | None = None
    campaign_name: str | None = None
    exploit_maturity: str | None = None
    confidence: str | None = None
    ransomware_association: bool = False
    active_last_seen: str | None = None
    target_sector: str | None = None
    target_region: str | None = None
    summary: str | None = None


class AffectedAsset(BaseModel):
    asset_id: str | None = None
    asset_name: str | None = None
    vuln_id: str | None = None
    vulnerability_name: str | None = None
    business_service: str | None = None
    criticality: str | None = None
    asset_exposure: str | None = None
    score: float | None = None


class CampaignDetail(BaseModel):
    threat_actor: str | None = None
    campaign_name: str | None = None
    target_profile: str | None = None
    exploit_chain: str | None = None
    ransomware: str | None = None
    confidence: str | None = None
    narrative: str | None = None
    iocs: str | None = None


class RiskExplanationOut(BaseModel):
    why_it_ranks: str
    remediation: str
    source: str


class RelatedControl(BaseModel):
    control_id: str | None = None
    control_name: str | None = None
    page: int | None = None
    distance: float | None = None
    confidence: str | None = None


class ScoredRisk(_Row):
    vuln_id: str | None = None
    asset_id: str | None = None
    cve: str | None = None
    id_type: str | None = None
    score: float | None = None
    kev_matched: bool | None = None
    kev_status: str | None = None
    kev_ransomware_use: bool | None = None
    kev_required_action: str | None = None
    kev_date_added: str | None = None
    active_campaign_matched: bool | None = None
    active_ransomware_campaign: bool | None = None


class TopRisk(_Row):
    risk_id: str | None = None
    id_type: str | None = None
    vulnerability_name: str | None = None
    alias_names: list[str] = Field(default_factory=list)
    score: float | None = None
    max_asset_score: float | None = None
    cvss: float | None = None
    severity: str | None = None
    asset_count: int | None = None
    internet_exposed_asset_count: int | None = None
    affected_assets: list[AffectedAsset] = Field(default_factory=list)
    business_services: list[str] = Field(default_factory=list)
    max_criticality: str | None = None
    kev_matched: bool | None = None
    kev_status: str | None = None
    kev_ransomware_use: bool | None = None
    kev_required_action: str | None = None
    kev_date_added: str | None = None
    active_campaign_matched: bool | None = None
    active_ransomware_campaign: bool | None = None
    threat_intel: list[ThreatIntelItem] = Field(default_factory=list)
    related_controls: list[RelatedControl] = Field(default_factory=list)
    nist_control_id: str | None = None
    nist_control_name: str | None = None
    nist_control_excerpt: str | None = None
    nist_page: int | None = None
    retrieval_distance: float | None = None
    retrieval_confidence: str | None = None
    campaign_detail: CampaignDetail | None = None
    explanation: RiskExplanationOut | None = None
