# Layer the exchange API/UI onto the exact installed portal OR console image.
# The existing codec, endpoint and entrypoint stay in the base.
# Upgrade console revocation forwarding when building a sidecar candidate.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}
USER root
COPY server/upstream/app/templates /tmp/apex-portal/templates
COPY server/upstream/app/static /tmp/apex-portal/static
COPY deploy/apply-design-system.py /tmp/apply-design-system.py
RUN python /tmp/apply-design-system.py /tmp/apex-portal /app/app && rm -rf /tmp/apex-portal /tmp/apply-design-system.py
COPY server/overlay/app/ /app/app/
COPY server/console/console_app.py /tmp/rtrust-console-update.py
COPY deploy/portal_patch.py /tmp/rtrust-portal-patch.py
RUN python /tmp/rtrust-portal-patch.py && \
    if [ -d /console ]; then cp /tmp/rtrust-console-update.py /console/console_app.py; fi && \
    rm /tmp/rtrust-portal-patch.py /tmp/rtrust-console-update.py
USER 10001:10001
