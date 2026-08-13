import os
import re
import requests
from pypdf import PdfReader
from app.core.config import settings

MAX_CHUNK_CHARS = 2000
CHUNK_OVERLAP_CHARS = 200
_CONTROL_HEADER_RE = re.compile("^([A-Z]{2}-\\d{1,2})\\s+([A-Z][A-Z0-9 ,\\-/&()'’]{3,})$")
_BOILERPLATE_RE = re.compile(
    "^(NIST SP 800-53, REV\\. 5|SECURITY AND PRIVACY CONTROLS FOR|CHAPTER \\w+\\s+PAGE|This publication is available free of charge|_{10,}|\\s*$)"
)


def fetch_nist_pdf(force_refresh: bool = False) -> str:
    path = settings.nist_pdf_path
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if force_refresh or not os.path.exists(path):
        resp = requests.get(settings.nist_pdf_url, timeout=120)
        resp.raise_for_status()
        with open(path, "wb") as f:
            f.write(resp.content)
    return path


def _clean_lines(pdf_path: str) -> list[tuple[str, int]]:
    reader = PdfReader(pdf_path)
    lines: list[tuple[str, int]] = []
    for page_num, page in enumerate(reader.pages, start=1):
        for raw in (page.extract_text() or "").split("\n"):
            line = raw.rstrip()
            if _BOILERPLATE_RE.match(line.strip()):
                continue
            lines.append((line, page_num))
    return lines


def _split_into_controls(lines: list[tuple[str, int]]) -> list[dict]:
    sections: list[dict] = []
    current: dict | None = None
    for line, page in lines:
        header = _CONTROL_HEADER_RE.match(line.strip())
        if header:
            if current:
                sections.append(current)
            current = {
                "control_id": header.group(1),
                "control_name": header.group(2).strip().title(),
                "page": page,
                "body": [],
            }
            continue
        if current:
            current["body"].append((line, page))
    if current:
        sections.append(current)
    out = []
    for s in sections:
        text = "\n".join(line for line, _ in s["body"])
        if len(text.strip()) < 120 or text.strip().lower().startswith("[withdrawn"):
            continue
        page_at = []
        for line, page in s["body"]:
            page_at.extend([page] * (len(line) + 1))
        s["text"] = text
        s["page_at"] = page_at
        out.append(s)
    return out


def _split_long(text: str) -> list[tuple[str, int]]:
    if len(text) <= MAX_CHUNK_CHARS:
        return [(text, 0)]
    parts, start = ([], 0)
    while start < len(text):
        end = start + MAX_CHUNK_CHARS
        parts.append((text[start:end], start))
        start = end - CHUNK_OVERLAP_CHARS
    return parts


def load_control_chunks() -> list[dict]:
    controls = _split_into_controls(_clean_lines(fetch_nist_pdf()))
    chunks = []
    for section in controls:
        page_at = section["page_at"]
        for i, (part, offset) in enumerate(_split_long(section["text"])):
            page = page_at[offset] if offset < len(page_at) else section["page"]
            chunks.append(
                {
                    "id": f"{section['control_id']}_{section['page']}_{i}",
                    "text": f"{section['control_id']} {section['control_name']}\n{part}",
                    "control_id": section["control_id"],
                    "control_name": section["control_name"],
                    "page": page,
                }
            )
    return chunks
