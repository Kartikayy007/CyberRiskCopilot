def risk_facts(risk: dict) -> str:
    assets = ", ".join((a["asset_name"] for a in risk.get("affected_assets", [])[:6])) or "unknown"
    services = ", ".join(risk.get("business_services") or []) or "unknown"
    intel = risk.get("threat_intel") or []
    if intel:
        t = intel[0]
        intel_line = f'{t.get('threat_actor')} running campaign "{t.get('campaign_name')}" ({t.get('exploit_maturity')}, {t.get('confidence')} confidence{(', ransomware-associated' if t.get('ransomware_association') else '')}). {t.get('summary') or ''}'
    else:
        intel_line = "No matching threat intelligence record."
    detail = risk.get("campaign_detail") or {}
    if detail:
        campaign_line = "\nMDR advisory on this campaign: " + " ".join(
            x
            for x in (
                detail.get("exploit_chain") and f"Exploit chain: {detail['exploit_chain']}.",
                detail.get("ransomware") and f"Ransomware: {detail['ransomware']}.",
                detail.get("narrative"),
            )
            if x
        )
    else:
        campaign_line = ""
    components = risk.get("component_scores") or {}
    drivers = ", ".join(
        (f"{k}={v}" for k, v in sorted(components.items(), key=lambda kv: kv[1], reverse=True)[:3])
    )
    return f"Identifier: {risk.get('risk_id')}\nVulnerability: {risk.get('vulnerability_name')}\nAffected assets ({risk.get('asset_count')}): {assets}\nInternet-exposed assets: {risk.get('internet_exposed_asset_count')}\nBusiness services: {services} (highest criticality: {risk.get('max_criticality')})\nCVSS: {risk.get('cvss')} | Composite risk score: {risk.get('score')}\nListed in CISA KEV (actively exploited): {risk.get('kev_matched')}\nMatched ransomware campaign: {risk.get('ransomware_campaign_matched')}\nThreat intelligence: {intel_line}{campaign_line}\nTop score drivers: {drivers}"


def build_prompt(risk: dict, control_id: str | None, control_name: str | None, chunk: str) -> str:
    control = f"{control_id} {control_name}".strip() if control_id else "the control below"
    return (
        "You are a security analyst briefing a technical manager.\n\n"
        f"{risk_facts(risk)}\n\n"
        f"Retrieved NIST SP 800-53 Rev.5 control ({control}), verbatim:\n"
        f"'''{chunk[:2500]}'''\n\n"
        "Return JSON with exactly these two keys:\n"
        '- "why_it_ranks": one sentence explaining why this risk ranks where it does. Reference\n'
        "  the concrete drivers above (exposure, active exploitation, the named campaign,\n"
        "  business impact).\n"
        f'- "remediation": two or three sentences applying {control} to THIS specific risk.\n'
        "  Base it only on the control text above.\n\n"
        "Rules: plain prose only. No markdown, no headings, no bullet points, no asterisks.\n"
        "Do not invent control identifiers."
    )


RETRY_SUFFIX = "\n\nYour previous reply was not valid JSON. Return only the JSON object."
