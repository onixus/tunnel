# Replaces only the endpoint binary; the portal, routing adapter and data layout stay as installed.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}
USER root
COPY trusttunnel_endpoint /opt/trusttunnel/trusttunnel_endpoint
RUN chmod 0755 /opt/trusttunnel/trusttunnel_endpoint
USER 10001:10001
