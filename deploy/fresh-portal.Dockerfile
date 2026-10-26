# Source bundle includes the pinned client source, including its Cargo.lock.
FROM rust:1.98.1-bookworm AS codec
WORKDIR /src
COPY client-source/ ./
RUN cargo build --locked --release -p rtrust-codec
FROM python:3.12-slim-bookworm
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 DATA_DIR=/data ENDPOINT_WORKDIR=/data/runtime CERT_DIR=/certs
WORKDIR /app
COPY server/upstream/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt
COPY server/upstream/app ./app
COPY server/overlay/app ./app
COPY --from=codec /src/target/release/rtrust-codec /usr/local/bin/rtrust-codec
COPY deploy/portal_patch.py /tmp/portal_patch.py
RUN python /tmp/portal_patch.py && rm /tmp/portal_patch.py
# UI starts before any VPN endpoint is installed.
USER 10001:10001
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
