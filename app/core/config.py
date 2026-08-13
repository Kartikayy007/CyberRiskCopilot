import os
from dataclasses import dataclass, field
from pathlib import Path

_APP_DIR = Path(__file__).resolve().parents[1]
_REPO_DIR = Path(__file__).resolve().parents[2]


def _abs(env_var: str, default: Path) -> str:
    return os.path.abspath(os.getenv(env_var) or default)


@dataclass(frozen=True)
class Settings:
    app_dir: str = str(_APP_DIR)
    repo_dir: str = str(_REPO_DIR)
    dataset_dir: str = str(_APP_DIR / "data" / "dataset")
    kev_url: str = (
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )
    kev_cache_dir: str = str(_APP_DIR / "data" / "kev")
    kev_cache_path: str = str(_APP_DIR / "data" / "kev" / "kev_catalog.json")
    nist_pdf_url: str = "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf"
    nist_pdf_path: str = field(
        default_factory=lambda: _abs(
            "NIST_800_53_PDF_PATH", _APP_DIR / "data" / "nist" / "sp800-53r5.pdf"
        )
    )
    chroma_dir: str = field(
        default_factory=lambda: _abs("CHROMA_PERSIST_DIR", _REPO_DIR / "chroma_store")
    )
    chroma_collection: str = "nist_800_53_r5_controls"
    embed_model: str = "all-MiniLM-L6-v2"
    groq_model: str = field(default_factory=lambda: os.getenv("GROQ_MODEL", "openai/gpt-oss-120b"))

    def groq_api_key(self) -> str | None:
        return os.getenv("GROQ_API_KEY")


settings = Settings()
