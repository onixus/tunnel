# Layer the exchange API/UI onto the exact installed portal OR console image.
# The existing codec, endpoint and entrypoint stay in the base.
# Upgrade console revocation forwarding when building a sidecar candidate.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}
USER root
# Route modules come along so the script can refuse a different portal version.
COPY server/upstream/app /tmp/apex-portal
COPY deploy/apply-design-system.py /tmp/apply-design-system.py
RUN python /tmp/apply-design-system.py /tmp/apex-portal /app/app && rm -rf /tmp/apex-portal /tmp/apply-design-system.py
COPY server/overlay/app/ /app/app/
COPY server/console/ /tmp/rtrust-console-update/
COPY deploy/portal_patch.py /tmp/rtrust-portal-patch.py
RUN python /tmp/rtrust-portal-patch.py && \
    if [ -d /console ]; then \
        cp /tmp/rtrust-console-update/console_app.py /console/console_app.py && \
        cp -R /tmp/rtrust-console-update/templates /tmp/rtrust-console-update/static /console/; \
    fi && \
    rm -rf /tmp/rtrust-portal-patch.py /tmp/rtrust-console-update
USER 10001:10001
