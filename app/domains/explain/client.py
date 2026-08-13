import os
from app.core.config import settings

MAX_ATTEMPTS = 3
RETRY_BACKOFF_SECONDS = 8
REQUEST_TIMEOUT_SECONDS = 30.0
MAX_TOKENS = 1200
REASONING_EFFORT = "low"
_client = None

RESPONSE_SCHEMA = {
    "type": "json_schema",
    "json_schema": {
        "name": "risk_explanation",
        "strict": True,
        "schema": {
            "type": "object",
            "properties": {
                "why_it_ranks": {"type": "string"},
                "remediation": {"type": "string"},
            },
            "required": ["why_it_ranks", "remediation"],
            "additionalProperties": False,
        },
    },
}


def get_client():
    global _client
    if _client is None:
        from groq import Groq

        _client = Groq(
            api_key=os.environ["GROQ_API_KEY"], timeout=REQUEST_TIMEOUT_SECONDS, max_retries=1
        )
    return _client


def complete_json(prompt: str, temperature: float) -> str:
    kwargs = {}
    if settings.groq_model.startswith("openai/gpt-oss"):
        kwargs["reasoning_effort"] = REASONING_EFFORT
    completion = get_client().chat.completions.create(
        model=settings.groq_model,
        messages=[{"role": "user", "content": prompt}],
        temperature=temperature,
        max_tokens=MAX_TOKENS,
        response_format=RESPONSE_SCHEMA,
        **kwargs,
    )
    return completion.choices[0].message.content


def is_retryable(exc: Exception) -> bool:
    status = getattr(exc, "status_code", None)
    if status in (408, 409, 429) or (isinstance(status, int) and status >= 500):
        return True
    text = str(exc).lower()
    return any(
        (
            t in text
            for t in (
                "rate limit",
                "429",
                "timeout",
                "temporarily",
                "json_validate_failed",
                "failed to generate json",
            )
        )
    )
