FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends qemu-system-x86 qemu-utils ovmf genisoimage curl ca-certificates openssh-client python3 && rm -rf /var/lib/apt/lists/*
WORKDIR /lab
CMD ["sleep", "infinity"]
