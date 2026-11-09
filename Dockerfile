FROM python:3.14-slim-trixie

COPY docker/install-jadx.sh /tmp/install-jadx.sh
RUN sh /tmp/install-jadx.sh && rm /tmp/install-jadx.sh

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
COPY config ./config
# Editable on purpose: config.py locates config/ and data/ relative to the source tree.
RUN pip install --no-cache-dir -e .

# compose.yaml may run this as a host UID with no passwd entry, so nothing can rely on a real home.
ENV HOME=/tmp JADX_CACHE_DIR=/tmp/jadx/cache JADX_CONFIG_DIR=/tmp/jadx/config PYTHONUNBUFFERED=1
USER 1000:1000
ENTRYPOINT ["vulnscan"]
