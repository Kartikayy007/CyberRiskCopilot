import os
from groq import Groq

_client = None


def _get_client():
    global _client
    if _client is None:
        _client = Groq(api_key=os.environ["GROQ_API_KEY"])
    return _client


def explain_risk(risk: dict, nist_chunk: str) -> str:
    """One LLM call: turn a scored risk + retrieved NIST chunk into plain-English explanation + remediation."""
    prompt = f"""You are a security analyst writing one short paragraph for a technical manager.

Risk data:
- Asset: {risk.get('asset_name')}
- Vulnerability: {risk.get('vulnerability_name')} ({risk.get('cve')})
- Business service at risk: {risk.get('business_service')} (criticality: {risk.get('criticality')})
- KEV-listed (actively exploited in the wild): {risk.get('kev_matched')}
- Matched ransomware campaign: {risk.get('ransomware_campaign_matched')}
- Composite risk score: {risk.get('score')}

Relevant NIST SP 800-53 control excerpt (retrieved, not memorized):
\"\"\"{nist_chunk}\"\"\"

Write two short parts:
1. WHY THIS RANKS HERE — one plain-English sentence.
2. REMEDIATION — one or two sentences applying the NIST control above to this specific risk.
"""

    client = _get_client()
    completion = client.chat.completions.create(
        model="llama-3.1-8b-instant",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.2,
    )
    return completion.choices[0].message.content
