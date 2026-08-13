# Koyeb free instance (512MB / 0.1 vCPU). Embeddings run on onnxruntime, not torch,
# which is what keeps this under the memory ceiling.
#
# The NIST PDF download, the 861-chunk embedding pass and the ONNX model download all
# happen at BUILD time. On 0.1 vCPU, doing any of that on the first request would
# blow past the health-check grace period.

FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    HOME=/app \
    CHROMA_PERSIST_DIR=/app/chroma_store \
    NIST_800_53_PDF_PATH=/app/app/data/nist/sp800-53r5.pdf \
    PORT=8000

# uid 1000 owns everything: Chroma opens its SQLite file read-write, and HOME must
# match between build and runtime or the ONNX model cache is re-downloaded on boot.
RUN useradd -m -u 1000 -d /app appuser
WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY --chown=appuser:appuser app ./app

USER appuser

RUN python -c "\
from app.domains.rag.store import build_or_load_collection; \
print('nist_chunks', build_or_load_collection().count())"

EXPOSE 8000

CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000} --workers 1"]
