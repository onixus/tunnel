# Native Linux test environment. Playwright package and browser image must match.
FROM rust:1.98.1-bookworm AS rust
FROM docker:29-cli AS docker-cli
FROM mcr.microsoft.com/playwright:v1.63.0-noble
USER root
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3-venv python3-pip git curl ca-certificates openssl libcairo2 pkg-config build-essential \
    && rm -rf /var/lib/apt/lists/*
COPY --from=rust /usr/local/cargo /usr/local/cargo
COPY --from=rust /usr/local/rustup /usr/local/rustup
COPY --from=docker-cli /usr/local/bin/docker /usr/local/bin/docker
ENV RUSTUP_HOME=/usr/local/rustup CARGO_HOME=/usr/local/cargo
ENV PATH=/opt/tests/bin:/usr/local/cargo/bin:$PATH
COPY server/test-environment/requirements.txt /tmp/requirements.txt
RUN python3 -m venv /opt/tests && pip install --no-cache-dir -r /tmp/requirements.txt \
    pytest 'playwright==1.63.0' cairosvg opencv-python-headless
