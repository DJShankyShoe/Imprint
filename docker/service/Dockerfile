# Imprint service
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    IMPRINT_RULES_DIR=/opt/imprint/rules \
    IMPRINT_AUDIT_LOG=/data/audit/classifier_audit.jsonl

WORKDIR /opt/imprint

COPY scripts/imprint/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY scripts/imprint/service.py scripts/imprint/advisor.py scripts/imprint/classify.py \
     scripts/imprint/fingerprint_hash.py scripts/imprint/imprint_env.py ./
COPY scripts/imprint/rules ./rules

# Run as non-root user
RUN useradd --system --uid 10001 --home-dir /opt/imprint imprint \
    && mkdir -p /keys/payload /keys/session /data/audit \
    && chown -R imprint:imprint /keys /data
USER imprint

EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=5s --retries=12 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=4)"

CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "2", "--threads", "4", "--timeout", "90", \
     "--access-logfile", "-", "service:app"]
