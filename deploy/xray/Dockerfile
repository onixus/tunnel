# Xray-core for VLESS behind a CDN. The agent places the `xray` binary from the developers'
# release archive after checking the SHA-256 GitHub published for it.
FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY xray /usr/local/bin/xray
RUN chmod 0755 /usr/local/bin/xray
ENTRYPOINT ["/usr/local/bin/xray", "run", "-config", "/etc/xray/config.json"]
