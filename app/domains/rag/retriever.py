from app.core import state
from app.domains.rag import embedder


def search_nist(query: str, top_k: int = 3) -> list[dict]:
    if state.NIST_COLLECTION is None:
        raise RuntimeError("NIST collection not loaded — ingest has not completed")
    query_embedding = embedder.encode([query]).tolist()
    results = state.NIST_COLLECTION.query(query_embeddings=query_embedding, n_results=top_k)
    hits = []
    for doc, meta, dist in zip(
        results["documents"][0], results["metadatas"][0], results["distances"][0]
    ):
        hits.append(
            {
                "text": doc,
                "control_id": meta.get("control_id"),
                "control_name": meta.get("control_name"),
                "page": meta.get("page"),
                "distance": dist,
            }
        )
    return hits
