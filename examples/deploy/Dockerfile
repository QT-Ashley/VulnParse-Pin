# PyPI / Wheelhouse Self-Build Dockerfile for VulnParse-Pin v2.0.0 (Apache-2.0)
#
# Use the repository-root `Dockerfile` (`docker build -t vulnparse-pin:2.0.0 .`) to
# build directly from a git checkout, or pull the official attested multi-arch image:
#   docker pull ghcr.io/qt-ashley/vulnparse-pin:2.0.0
#
# Use this standalone Dockerfile when building from PyPI or an offline wheelhouse archive
# without cloning the full repository source tree.
#
# Build examples:
#   docker build -t vulnparse-pin:2.0.0 -f examples/deploy/Dockerfile .
#   docker build --build-arg VPP_PACKAGE="vulnparse-pin" -t vulnparse-pin:2.0.0-headless -f examples/deploy/Dockerfile .
#
# Run with read-only rootfs and mounted workspace/cache:
#   docker run --rm --read-only --cap-drop=ALL --security-opt=no-new-privileges:true \
#     --tmpfs /tmp:rw,noexec,nosuid \
#     -v "$PWD:/work" -v "vpp-cache:/cache" \
#     vulnparse-pin:2.0.0 demo --no-ui --output-dir /work/vpp_demo_output --db /work/.vpp-demo.db

# --- Stage 1: Build virtual environment and install wheels ---
FROM python:3.12-slim AS builder

ARG VPP_PACKAGE="vulnparse-pin[ui]"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN python -m venv /opt/vpp-venv \
    && /opt/vpp-venv/bin/pip install --no-cache-dir --upgrade pip

# To build 100% offline from a pre-downloaded wheelhouse, copy ./wheelhouse into /wheels
# and replace the install command below with:
#   /opt/vpp-venv/bin/pip install --no-cache-dir --no-index --find-links=/wheels "${VPP_PACKAGE}"
RUN /opt/vpp-venv/bin/pip install --no-cache-dir "${VPP_PACKAGE}"

# --- Stage 2: Minimal non-root runtime compatible with --read-only rootfs ---
FROM python:3.12-slim AS runtime

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
