from app import state
from app.rag.nist_ingest import _get_embedder


def search_nist(query: str, top_k: int = 3) -> list[dict]:
    if state.NIST_COLLECTION is None:
        raise RuntimeError("NIST collection not loaded — call /ingest first")

    embedder = _get_embedder()
    query_embedding = embedder.encode([query]).tolist()

    results = state.NIST_COLLECTION.query(query_embeddings=query_embedding, n_results=top_k)

    hits = []
    for doc, meta, dist in zip(results["documents"][0], results["metadatas"][0], results["distances"][0]):
        hits.append({"text": doc, "page": meta.get("page"), "distance": dist})
    return hits
