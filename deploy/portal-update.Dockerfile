# Layer the exchange API/UI onto the exact installed portal OR console image.
# The existing codec, endpoint binary, console and entrypoint stay in the base.
# The supervisor gains generation-fenced, explicitly consented credential reload.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}
USER root
COPY server/overlay/app/ /app/app/
COPY server/upstream/app/endpoint.py /app/app/endpoint.py
COPY deploy/portal_patch.py /tmp/rtrust-portal-patch.py
RUN python /tmp/rtrust-portal-patch.py && rm /tmp/rtrust-portal-patch.py
USER 10001:10001
