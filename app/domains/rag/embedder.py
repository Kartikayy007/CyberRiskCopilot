import threading
from app.core.config import settings

_embedder = None
_encode_lock = threading.Lock()


def get_embedder():
    global _embedder
    if _embedder is None:
        from sentence_transformers import SentenceTransformer

        _embedder = SentenceTransformer(settings.embed_model)
    return _embedder


def encode(texts: list[str], **kwargs):
    model = get_embedder()
    with _encode_lock:
        return model.encode(texts, **kwargs)
