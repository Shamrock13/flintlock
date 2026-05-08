# Refresh digest quarterly for security patches
FROM python:3.11-slim@sha256:233de06753d30d120b1a3ce359d8d3be8bda78524cd8f520c99883bfe33964cf

RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

# Install dependencies first (layer caching)
COPY requirements.txt .
RUN mkdir -p /ms-playwright \
    && pip install -r requirements.txt \
    && python -m playwright install --with-deps chromium

# Copy source
COPY . .

# Persistent data directories (uploads, reports, license, encryption key)
RUN mkdir -p /data/uploads /data/reports

# Create non-root user and set ownership
RUN useradd -m -u 1000 cashel \
    && chown -R cashel:cashel /app /data /ms-playwright \
    && chmod -R a+rX /ms-playwright
USER cashel

# Environment defaults (overridable via docker-compose or -e flags)
ENV PYTHONPATH=/app/src
ENV UPLOAD_FOLDER=/data/uploads
ENV REPORTS_FOLDER=/data/reports
ENV LICENSE_PATH=/data/.cashel_license
ENV CASHEL_KEY_FILE=/data/cashel.key

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f "http://localhost:${PORT:-5000}/" || exit 1

CMD ["gunicorn", "--config", "gunicorn.conf.py", "cashel.web:app"]
