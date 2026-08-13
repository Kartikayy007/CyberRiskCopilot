import chromadb
from app.core.config import settings
from app.domains.rag import embedder
from app.domains.rag.document import load_control_chunks


def build_or_load_collection(force_rebuild: bool = False):
    client = chromadb.PersistentClient(path=settings.chroma_dir)
    name = settings.chroma_collection
    existing = [c.name for c in client.list_collections()]
    if name in existing and (not force_rebuild):
        collection = client.get_collection(name)
        if collection.count() > 0:
            return collection
        client.delete_collection(name)
    elif name in existing:
        client.delete_collection(name)
    collection = client.create_collection(name)
    chunks = load_control_chunks()
    if chunks:
        texts = [c["text"] for c in chunks]
        embeddings = embedder.encode(texts, show_progress_bar=False).tolist()
        collection.add(
            ids=[c["id"] for c in chunks],
            documents=texts,
            metadatas=[
                {
                    "control_id": c["control_id"],
                    "control_name": c["control_name"],
                    "page": c["page"],
                }
                for c in chunks
            ],
            embeddings=embeddings,
        )
    return collection
