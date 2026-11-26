# SPDX-License-Identifier: Apache-2.0
# Portable Source-Built Container Image for VulnParse-Pin (Apache-2.0)
#
# Build directly from this repository checkout:
#   docker build -t vulnparse-pin:2.0.0 .
#   docker build --build-arg EXTRAS="" -t vulnparse-pin:2.0.0-headless .
#
# Run offline demo with read-only rootfs, dropped capabilities, and mounted workspace/cache:
#   docker run --rm --read-only --cap-drop=ALL --security-opt=no-new-privileges:true \
#     --tmpfs /tmp:rw,noexec,nosuid \
#     -v "$PWD:/work" -v "vpp-cache:/cache" \
#     vulnparse-pin:2.0.0 demo --no-ui --output-dir /work/vpp_demo_output --db /work/.vpp-demo.db

# --- Stage 1: Build virtual environment and install VulnParse-Pin from source ---
FROM python:3.12-slim AS builder

ARG EXTRAS="ui"
ARG PIP_NO_INDEX="0"
ARG PIP_FIND_LINKS=""

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

COPY pyproject.toml README.md LICENSE NOTICE ./
COPY src/ ./src/

RUN python -m venv /opt/vpp-venv \
    && if [ "$PIP_NO_INDEX" != "1" ]; then \
         /opt/vpp-venv/bin/pip install --no-cache-dir --upgrade pip; \
       fi \
    && target="/build" \
    && if [ -n "$EXTRAS" ]; then target="/build[${EXTRAS}]"; fi \
    && if [ "$PIP_NO_INDEX" = "1" ] && [ -n "$PIP_FIND_LINKS" ]; then \
         /opt/vpp-venv/bin/pip install --no-cache-dir --no-index --find-links="$PIP_FIND_LINKS" "$target"; \
       else \
         /opt/vpp-venv/bin/pip install --no-cache-dir "$target"; \
       fi

# --- Stage 2: Minimal non-root runtime compatible with --read-only rootfs ---
FROM python:3.12-slim AS runtime

ARG VPP_VERSION="2.0.0"

LABEL org.opencontainers.image.title="VulnParse-Pin" \
      org.opencontainers.image.description="Audit-defensible vulnerability triage, BOD 26-04 SSVC decisioning, and multi-scanner normalization engine (vpp)." \
      org.opencontainers.image.version="${VPP_VERSION}" \
      org.opencontainers.image.source="https://github.com/QT-Ashley/VulnParse-Pin" \
      org.opencontainers.image.documentation="https://qt-ashley.github.io/VulnParse-Pin/" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="Quashawn Ashley"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/vpp-venv/bin:${PATH}" \
    HOME="/work" \
    XDG_DATA_HOME="/cache/data" \
    XDG_CONFIG_HOME="/cache/config" \
    XDG_CACHE_HOME="/cache/xdg" \
    TMPDIR="/tmp" \
    TERM="xterm-256color"

RUN groupadd --gid 10001 vpp \
    && useradd --uid 10001 --gid 10001 --home-dir /work --shell /usr/sbin/nologin vpp \
    && mkdir -p /work /cache/data /cache/config /cache/xdg \
    && chown -R 10001:10001 /work /cache

COPY --from=builder /opt/vpp-venv /opt/vpp-venv

USER 10001:10001
WORKDIR /work

VOLUME ["/work", "/cache"]

ENTRYPOINT ["vpp"]
CMD ["--help"]
