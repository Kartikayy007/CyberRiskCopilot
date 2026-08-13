import threading
import numpy as np

_embedder = None
_encode_lock = threading.Lock()


def get_embedder():
    """all-MiniLM-L6-v2 via onnxruntime — same weights as the sentence-transformers
    build, without the torch dependency. torch pushed RSS past the 512MB free-tier
    ceiling on every card-free host."""
    global _embedder
    if _embedder is None:
        from chromadb.utils.embedding_functions import ONNXMiniLM_L6_V2

        _embedder = ONNXMiniLM_L6_V2()
    return _embedder


def encode(texts: list[str], **kwargs):
    """kwargs are accepted and ignored (e.g. show_progress_bar) so callers stay
    unchanged. Returns a numpy array, as the sentence-transformers version did."""
    model = get_embedder()
    with _encode_lock:
        return np.asarray(model(list(texts)), dtype=np.float32)
