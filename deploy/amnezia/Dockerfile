# AmneziaWG server built from pinned developer tags and commits, plus the exit router.
FROM golang:1.25 AS awg
ARG AWG_GO_REF
ARG AWG_GO_COMMIT
RUN git clone --depth 1 --branch "${AWG_GO_REF}" https://github.com/amnezia-vpn/amneziawg-go.git /awg && \
    test "$(git -C /awg rev-parse HEAD)" = "${AWG_GO_COMMIT}"
WORKDIR /awg
RUN printf 'package main\n\nconst Version = "%s"\n' "${AWG_GO_REF#v}" > version.go && \
    go mod download && go mod verify && \
    CGO_ENABLED=0 go build -trimpath -o /out/amneziawg-go .

# Match the C tools to the glibc runtime needed by official sing-box 1.14 binaries.
FROM debian:trixie-slim AS tools
ARG AWG_TOOLS_REF
ARG AWG_TOOLS_COMMIT
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates git build-essential linux-libc-dev && rm -rf /var/lib/apt/lists/* && \
    git clone --depth 1 --branch "${AWG_TOOLS_REF}" https://github.com/amnezia-vpn/amneziawg-tools.git /tools && \
    test "$(git -C /tools rev-parse HEAD)" = "${AWG_TOOLS_COMMIT}" && \
    make -C /tools/src && \
    sed -i '/^add_if() {$/,/^}$/c\add_if() {\n\tcmd amneziawg-go "$INTERFACE"\n}' /tools/src/wg-quick/linux.bash && \
    grep -qx "$(printf '\tcmd amneziawg-go "$INTERFACE"')" /tools/src/wg-quick/linux.bash && \
    ! grep -q 'type amneziawg' /tools/src/wg-quick/linux.bash

FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      bash ca-certificates iproute2 iptables procps libstdc++6 && rm -rf /var/lib/apt/lists/*
COPY --from=tools /tools/src/wg /usr/bin/awg
COPY --from=tools /tools/src/wg-quick/linux.bash /usr/bin/awg-quick
COPY --from=awg /out/amneziawg-go /usr/bin/amneziawg-go
# Keep the optional libcronet.so beside its binary, as in the verified developer archive.
COPY router/ /usr/lib/sing-box/
ENV LD_LIBRARY_PATH=/usr/lib/sing-box LOG_LEVEL=error
COPY entrypoint.sh /entrypoint.sh
RUN chmod 0755 /usr/bin/awg /usr/bin/awg-quick /usr/bin/amneziawg-go /usr/lib/sing-box/* /entrypoint.sh && \
    ln -s /usr/lib/sing-box/sing-box /usr/bin/sing-box && sing-box version
ENTRYPOINT ["/entrypoint.sh"]
