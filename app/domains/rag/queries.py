def build_situation_query(risk: dict) -> str:
    name = f"{risk.get('vulnerability_name') or ''} {risk.get('affected_component') or ''}".lower()

    def has(*terms) -> bool:
        return any((t in name for t in terms))

    if has("end of support", "end-of-life", "unsupported", "eol", "obsolete"):
        situation = "A system component is no longer supported by the developer or vendor and no longer receives security updates. Replacement, or approved compensating controls and alternative sources of support, are required."
    elif has("edr", "endpoint", "antivirus", "malware", "agent"):
        situation = "Endpoints have no malicious code protection agent installed. Protection mechanisms must be deployed at system entry and exit points, kept updated, and configured to scan and block malicious code."
    elif has(
        "credential",
        "password",
        "session",
        "token",
        "authentication",
        "mfa",
        "account",
        "privilege",
    ):
        situation = "Account credentials and session tokens can be captured or reused to bypass authentication. Accounts and sessions must be managed, monitored, and terminated appropriately, and authenticators protected."
    elif has("misconfigur", "exposed", "public", "default config", "hardening", "permissive"):
        situation = "A system is deployed with an insecure configuration that exposes services. Secure baseline configuration settings must be established, documented, and enforced, and deviations monitored."
    elif str(risk.get("patch_available")).strip().lower() == "yes":
        situation = "A software flaw on a production system is being actively exploited. A vendor security update is available and must be tested and installed within a defined time period, with remediation tracked."
    else:
        situation = "Vulnerabilities on systems and hosted applications must be monitored and scanned at a defined frequency, scan reports analysed, and legitimate vulnerabilities remediated according to organizational risk."
    if risk.get("ransomware_campaign_matched"):
        situation += " The weakness is under active exploitation by an adversary campaign, so incident handling and containment also apply."
    return situation
