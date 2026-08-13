ID_LABEL = {"cve": "CVE", "synthetic_cve": "Synthetic CVE", "control_finding": "Control gap"}


def _format_intel(risk: dict) -> list[str]:
    intel = risk.get("threat_intel") or []
    if not intel:
        return [
            "**Matched threat intel:** none — this risk ranks on exposure, exploitability and control gaps alone.\n"
        ]
    lines = ["**Matched threat intel**"]
    for t in intel:
        traits = [t.get("exploit_maturity"), f"{t.get('confidence')} confidence"]
        if t.get("ransomware_association"):
            traits.append("ransomware-associated")
        if t.get("active_last_seen"):
            traits.append(f"last seen {t['active_last_seen']}")
        lines.append(
            f'- {t.get('threat_actor')} / "{t.get('campaign_name')}" — '
            + ", ".join((str(x) for x in traits if x))
        )
        targeting = ", ".join(
            (str(x) for x in (t.get("target_sector"), t.get("target_region")) if x)
        )
        if targeting:
            lines.append(f"  Targeting: {targeting}")
        if t.get("summary"):
            lines.append(f"  > {t['summary']}")
    lines += _format_campaign_detail(risk)
    lines.append("")
    return lines


def _format_campaign_detail(risk: dict) -> list[str]:
    detail = risk.get("campaign_detail")
    if not detail:
        return []
    lines = ["", "  Campaign detail (MDR advisory):"]
    for label, key in (
        ("Exploit chain", "exploit_chain"),
        ("Ransomware", "ransomware"),
        ("Target profile", "target_profile"),
    ):
        if detail.get(key):
            lines.append(f"  - {label}: {detail[key]}")
    if detail.get("narrative"):
        lines.append(f"  - Tradecraft: {detail['narrative']}")
    if detail.get("iocs"):
        lines.append(f"  - IOCs: {detail['iocs']}")
    return lines


def render_report(risks: list[dict]) -> str:
    lines = [
        "# TawasolPay — Top 5 Cyber Risks",
        "",
        "Ranked by composite risk score: internet exposure, active exploitation (CISA KEV), threat-actor campaign match, business-service criticality and missing compensating controls — not CVSS alone.",
        "",
    ]
    for i, r in enumerate(risks, 1):
        label = ID_LABEL.get(r.get("id_type"), "Finding")
        assets = ", ".join((a["asset_name"] for a in r.get("affected_assets", [])))
        services = ", ".join(r.get("business_services") or []) or "unmapped"
        explanation = r.get("explanation") or {}
        lines += [
            f"## {i}. {r.get('vulnerability_name')}",
            "",
            f"- **{label}:** {r.get('risk_id')}"
            + (f" · CVSS {r['cvss']}" if r.get("cvss") is not None else ""),
            f"- **Risk score:** {r.get('score')}",
            f"- **Affected assets ({r.get('asset_count')}):** {assets}"
            + (
                f" — {r['internet_exposed_asset_count']} internet-exposed"
                if r.get("internet_exposed_asset_count")
                else ""
            ),
            f"- **Business service at risk:** {services}"
            + (f" (criticality: {r['max_criticality']})" if r.get("max_criticality") else ""),
            f"- **Actively exploited (CISA KEV):** {('yes' if r.get('kev_matched') else 'no')}",
            "",
            "**Why this ranks here**",
            explanation.get("why_it_ranks", ""),
            "",
        ]
        lines += _format_intel(r)
        control = " ".join(
            (str(x) for x in (r.get("nist_control_id"), r.get("nist_control_name")) if x)
        )
        lines += [
            f"**Remediation — NIST SP 800-53 Rev.5 {control}"
            + (f" (p.{r['nist_page']})" if r.get("nist_page") is not None else "")
            + "**",
            explanation.get("remediation", ""),
        ]
        related = r.get("related_controls") or []
        if related:
            lines.append("")
            lines.append(
                "Related controls: "
                + "; ".join(
                    f"{c.get('control_id')} {c.get('control_name')}"
                    + (f" (p.{c['page']})" if c.get("page") is not None else "")
                    for c in related
                )
                + "."
            )
        if r.get("retrieval_confidence") == "low":
            lines.append("")
            lines.append("_Low-confidence control match — verify before acting._")
        if explanation.get("source") == "fallback":
            lines.append("")
            lines.append("_Explanation generated from structured data (model unavailable)._")
        if r.get("alias_names"):
            lines.append("")
            lines.append(f"_Also reported as: {'; '.join(r['alias_names'])}._")
        lines += ["", "---", ""]
    return "\n".join(lines)
