#!/usr/bin/env bash
# Inside ci/fresh-install-vm.Dockerfile image. Isolated full x86_64 Linux VM.
set -euo pipefail
cd /lab
ssh-keygen -q -t ed25519 -N '' -f /lab/id_ed25519
printf 'instance-id: tunnel-installer-test\nlocal-hostname: tunnel-installer-test\n' > meta-data
cat > user-data <<CLOUD
#cloud-config
users:
  - name: tester
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    ssh_authorized_keys:
      - $(cat /lab/id_ed25519.pub)
ssh_pwauth: false
disable_root: true
CLOUD
genisoimage -quiet -output seed.iso -volid cidata -joliet -rock user-data meta-data
qemu-img create -f qcow2 -b "${IMAGE_FILE:-/lab/ubuntu.img}" -F qcow2 /lab/install-test.qcow2
qemu-img resize install-test.qcow2 24G
if [[ ${USE_KVM:-0} == 1 && -r /dev/kvm && -w /dev/kvm ]]; then
  accel=(-accel kvm -cpu host)
else
  accel=(-accel tcg,thread=multi -cpu max)
fi
firmware=()
if [[ ${VM_UEFI:-0} == 1 ]]; then
  cp /usr/share/OVMF/OVMF_VARS_4M.fd /lab/OVMF_VARS.fd
  firmware=(-drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd -drive if=pflash,format=raw,file=/lab/OVMF_VARS.fd)
fi
exec qemu-system-x86_64 -machine q35 "${accel[@]}" "${firmware[@]}" -smp 4 -m 4096 \
  -drive file=install-test.qcow2,format=qcow2,if=virtio \
  -drive file=seed.iso,format=raw,if=virtio,readonly=on \
  -netdev user,id=net0,hostfwd=tcp:0.0.0.0:2222-:22,hostfwd=tcp:0.0.0.0:18443-:18443 \
  -device virtio-net-pci,netdev=net0 -display none -serial file:/lab/serial.log -monitor none
