# Additive sidecar; VPN endpoint in the existing container is untouched.
ARG BASE_IMAGE=trusttunnel-web:profiles-20260930
FROM ${BASE_IMAGE}
USER root
COPY server/console /console
# Route modules come along so the script can refuse a different portal version.
COPY server/upstream/app /tmp/apex-portal
COPY deploy/apply-design-system.py /tmp/apply-design-system.py
RUN python /tmp/apply-design-system.py /tmp/apex-portal /app/app && rm -rf /tmp/apex-portal /tmp/apply-design-system.py
WORKDIR /app
ENV PYTHONPATH=/app:/console
USER 10001:10001
HEALTHCHECK --interval=30s --timeout=15s --start-period=30s --retries=3 CMD python -c "import urllib.request; assert urllib.request.urlopen('http://127.0.0.1:8000/console/healthz',timeout=10).status == 200"
CMD ["uvicorn", "routing_app:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
