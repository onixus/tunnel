#!/usr/bin/env bash
# Run from the extracted, checksum-verified source bundle.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
if [[ ${1:-} == --help || ${1:-} == -h ]]; then
    echo 'Установка: sudo bash tunnel-installer-<ubuntu24|centos-stream>-amd64.run [--address АДРЕС --email ЛОГИН --non-interactive] [--ssh-port ПОРТ]'
    echo 'Продолжить прерванную установку: sudo bash <инсталлятор.run> --resume'
    echo 'Нужна чистая Ubuntu 24.04 или CentOS Stream 9/10 x86_64 с systemd.'
    exit 0
fi
if [[ ${EUID} -ne 0 ]]; then
    echo 'Запустите: sudo bash deploy/install.sh' >&2
    exit 1
fi
if [[ ! -f /etc/os-release ]]; then echo 'Нет /etc/os-release' >&2; exit 1; fi
. /etc/os-release
host_family=''
if [[ $ID == ubuntu && $VERSION_ID == 24.04 ]]; then host_family=ubuntu24; fi
if [[ $ID == centos && ( $VERSION_ID == 9 || $VERSION_ID == 10 ) && ${NAME:-} == *Stream* ]]; then host_family=centos-stream; fi
if [[ -z $host_family || $(uname -m) != x86_64 || ! -d /run/systemd/system ]]; then
    echo 'Нужна Ubuntu 24.04 или CentOS Stream 9/10 x86_64 с systemd. CentOS 7/8 не поддерживаются.' >&2
    exit 1
fi
if [[ ${TUNNEL_INSTALL_TARGET:-$host_family} != "$host_family" ]]; then
    echo 'Этот пакет собран для другой ОС; скачайте соответствующий инсталлятор.' >&2
    exit 1
fi
if ! command -v python3 >/dev/null; then
    if [[ $host_family == ubuntu24 ]]; then apt-get update; apt-get install -y python3
    else dnf install -y python3; fi
fi
exec python3 deploy/install-fresh.py "$@"
