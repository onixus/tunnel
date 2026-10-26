# AmneziaWG server built from the developers' repositories at pinned tags, plus the exit router.
# The agent passes tags and the commits GitHub reported for them; a moved tag fails the build.
FROM golang:1.25 AS awg
ARG AWG_GO_REF
ARG AWG_GO_COMMIT
RUN git clone --depth 1 --branch "${AWG_GO_REF}" https://github.com/amnezia-vpn/amneziawg-go.git /awg && \
    test "$(git -C /awg rev-parse HEAD)" = "${AWG_GO_COMMIT}"
WORKDIR /awg
RUN go mod download && go mod verify && \
    CGO_ENABLED=0 go build -trimpath -o /out/amneziawg-go .

FROM alpine:3.19 AS tools
ARG AWG_TOOLS_REF
ARG AWG_TOOLS_COMMIT
RUN apk add --no-cache git build-base linux-headers && \
    git clone --depth 1 --branch "${AWG_TOOLS_REF}" https://github.com/amnezia-vpn/amneziawg-tools.git /tools && \
    test "$(git -C /tools rev-parse HEAD)" = "${AWG_TOOLS_COMMIT}" && \
    make -C /tools/src

FROM alpine:3.19
RUN apk add --no-cache bash iproute2 iptables
COPY --from=tools /tools/src/wg /usr/bin/awg
COPY --from=tools /tools/src/wg-quick/linux.bash /usr/bin/awg-quick
COPY --from=awg /out/amneziawg-go /usr/bin/amneziawg-go
# Official sing-box release; the agent checked the SHA-256 GitHub published for the archive.
COPY sing-box /usr/bin/sing-box
COPY entrypoint.sh /entrypoint.sh
RUN chmod 0755 /usr/bin/awg /usr/bin/awg-quick /usr/bin/amneziawg-go /usr/bin/sing-box /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
