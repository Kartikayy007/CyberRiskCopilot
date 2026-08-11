"""
Fetch NIST SP 800-53 Rev.5, chunk it, embed with sentence-transformers,
and store in a persistent ChromaDB collection. This is the RAG side —
the CSVs never go through this path, only this document does.
"""

import os
import requests
from pypdf import PdfReader
import chromadb
from sentence_transformers import SentenceTransformer

NIST_PDF_URL = "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf"
PDF_PATH = os.getenv(
    "NIST_800_53_PDF_PATH",
    os.path.join(os.path.dirname(__file__), "..", "data", "nist", "sp800-53r5.pdf"),
)
CHROMA_DIR = os.getenv("CHROMA_PERSIST_DIR", "./chroma_store")
COLLECTION_NAME = "nist_800_53_r5"
CHUNK_SIZE_CHARS = 1200
CHUNK_OVERLAP_CHARS = 200

_embedder = None


def _get_embedder():
    global _embedder
    if _embedder is None:
        _embedder = SentenceTransformer("all-MiniLM-L6-v2")
    return _embedder


def fetch_nist_pdf(force_refresh: bool = False) -> str:
    os.makedirs(os.path.dirname(PDF_PATH), exist_ok=True)
    if force_refresh or not os.path.exists(PDF_PATH):
        resp = requests.get(NIST_PDF_URL, timeout=60)
        resp.raise_for_status()
        with open(PDF_PATH, "wb") as f:
            f.write(resp.content)
    return PDF_PATH


def _chunk_text(text: str) -> list[str]:
    chunks = []
    start = 0
    while start < len(text):
        end = start + CHUNK_SIZE_CHARS
        chunks.append(text[start:end])
        start = end - CHUNK_OVERLAP_CHARS
    return [c.strip() for c in chunks if c.strip()]


def build_or_load_collection(force_rebuild: bool = False):
    client = chromadb.PersistentClient(path=CHROMA_DIR)

    existing = [c.name for c in client.list_collections()]
    if COLLECTION_NAME in existing and not force_rebuild:
        return client.get_collection(COLLECTION_NAME)

    if COLLECTION_NAME in existing:
        client.delete_collection(COLLECTION_NAME)
    collection = client.create_collection(COLLECTION_NAME)

    pdf_path = fetch_nist_pdf()
    reader = PdfReader(pdf_path)
    embedder = _get_embedder()

    ids, texts, metadatas = [], [], []
    for page_num, page in enumerate(reader.pages):
        page_text = page.extract_text() or ""
        for chunk_idx, chunk in enumerate(_chunk_text(page_text)):
            ids.append(f"p{page_num}_c{chunk_idx}")
            texts.append(chunk)
            metadatas.append({"page": page_num})

    if texts:
        embeddings = embedder.encode(texts, show_progress_bar=False).tolist()
        collection.add(ids=ids, documents=texts, metadatas=metadatas, embeddings=embeddings)

    return collection
