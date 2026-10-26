#!/usr/bin/env bash
# Inside the disposable QEMU helper, never on the actual server.
set -euo pipefail
cd /lab
centos_version=${1:-10}
[[ $centos_version == 9 || $centos_version == 10 ]]
image_name="CentOS-Stream-GenericCloud-${centos_version}-latest.x86_64.qcow2"
image_root="https://cloud.centos.org/centos/${centos_version}-stream/x86_64/images"
curl -fLsS --retry 3 "$image_root/$image_name" -o centos.img
curl -fsSL "$image_root/$image_name.SHA256SUM" -o CENTOS-SHA256SUM
python3 - <<'PY'
import hashlib,pathlib,re
expected=re.search(r'\b[0-9a-fA-F]{64}\b',pathlib.Path('CENTOS-SHA256SUM').read_text()).group().lower()
with open('centos.img','rb') as stream:
    actual=hashlib.file_digest(stream,'sha256').hexdigest()
assert actual==expected
pathlib.Path('image-sha256.txt').write_text(actual+'\n')
PY
IMAGE_FILE=/lab/centos.img VM_UEFI=1 USE_KVM=0 bash /lab/boot.sh > /lab/qemu.log 2>&1 &
qemu_pid=$!
ssh_options=(-i /lab/id_ed25519 -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10)
ready=false
for attempt in $(seq 1 90); do
  if ! kill -0 "$qemu_pid" 2>/dev/null; then cat /lab/qemu.log >&2; exit 1; fi
  if ssh "${ssh_options[@]}" -p 2222 tester@127.0.0.1 true 2>/dev/null; then ready=true; break; fi
  sleep 5
done
[[ $ready == true ]]
while [[ ! -f /lab/installer.run ]]; do sleep 3; done
scp "${ssh_options[@]}" -P 2222 installer.run protocols-test.py tester@127.0.0.1:/home/tester/
ssh "${ssh_options[@]}" -p 2222 tester@127.0.0.1 'set -e; cloud-init status --wait; cat /etc/os-release; test "$(getenforce)" = Enforcing; ! command -v docker; sudo touch /run/tunnel-disposable-install-test; sudo bash /home/tester/installer.run --non-interactive --address 10.0.2.15 --email admin@example.invalid' > /lab/install.log 2>&1 && install_result=0 || install_result=$?
printf '%s\n' "$install_result" > /lab/install.exit
if [[ $install_result -eq 0 ]]; then
  ssh "${ssh_options[@]}" -p 2222 tester@127.0.0.1 'sudo python3 /home/tester/protocols-test.py' > /lab/protocols.log 2>&1 && protocol_result=0 || protocol_result=$?
  printf '%s\n' "$protocol_result" > /lab/protocols.exit
fi
exit "${protocol_result:-$install_result}"
