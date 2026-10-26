# oauth-mail-mcp runtime image.
#
# one image, one mailbox per container. himalaya (IMAP/SMTP) + ortie (OAuth token
# broker) are pinned release binaries; server.py is the MCP surface.

FROM debian:trixie-slim

ARG TARGETARCH
ARG HIMALAYA_VERSION=2.2.1
ARG ORTIE_VERSION=2.3.0

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl python3 python3-venv \
 && rm -rf /var/lib/apt/lists/*

# Pinned upstream binaries. The release tarballs are per-architecture; TARGETARCH comes
# from buildx so one Dockerfile serves arm64 (MengeMac, Apple silicon) and amd64.
RUN set -eux; \
    case "${TARGETARCH:-amd64}" in \
      amd64) ARCH=x86_64 ;; \
      arm64) ARCH=aarch64 ;; \
      *) echo "unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/himalaya.tgz \
      "https://github.com/pimalaya/himalaya/releases/download/v${HIMALAYA_VERSION}/himalaya.${ARCH}-linux.tgz"; \
    mkdir -p /tmp/himalaya; \
    tar -xzf /tmp/himalaya.tgz -C /tmp/himalaya; \
    install -m 0755 /tmp/himalaya/himalaya /usr/local/bin/himalaya; \
    curl -fsSL -o /tmp/ortie.tgz \
      "https://github.com/pimalaya/ortie/releases/download/v${ORTIE_VERSION}/ortie.${ARCH}-linux.tgz"; \
    mkdir -p /tmp/ortie; \
    tar -xzf /tmp/ortie.tgz -C /tmp/ortie; \
    install -m 0755 /tmp/ortie/ortie /usr/local/bin/ortie; \
    rm -rf /tmp/himalaya /tmp/himalaya.tgz /tmp/ortie /tmp/ortie.tgz; \
    himalaya --version; ortie --version

COPY requirements.txt /app/requirements.txt
RUN python3 -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir -r /app/requirements.txt

COPY server.py /app/server.py

# `python` is not on PATH in Debian, and the venv holds the deps: give the container a stable
# command so `docker exec -it <container> mail auth-start` works without knowing either.
RUN printf '#!/bin/sh\nexec /opt/venv/bin/python /app/server.py "$@"\n' > /usr/local/bin/mail \
 && chmod 0755 /usr/local/bin/mail

# Non-root, and /data owned by that user so a fresh named volume inherits the right owner.
# Debian already ships a `mail` user, so use a project-specific name and pin uid/gid 1000.
RUN groupadd --gid 1000 mailmcp \
 && useradd --uid 1000 --gid 1000 --create-home --home-dir /home/mailmcp \
      --shell /usr/sbin/nologin mailmcp \
 && mkdir -p /data && chown mailmcp:mailmcp /data && chmod 700 /data

USER mailmcp
ENV HOME=/home/mailmcp \
    MAIL_DATA_DIR=/data

EXPOSE 8080 8081 8082
VOLUME ["/data"]

# 503 for unauthenticated / reauth-required / upstream-error is deliberate: a dead grant
# must show as unhealthy rather than hide behind a green container.
HEALTHCHECK --interval=60s --timeout=15s --start-period=30s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8081/health >/dev/null || exit 1

CMD ["/opt/venv/bin/python", "/app/server.py"]
