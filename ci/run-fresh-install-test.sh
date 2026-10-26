#!/usr/bin/env bash
set -euo pipefail
cd /lab
curl -fLsS --retry 3 https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img -o ubuntu.img
curl -fsSL https://cloud-images.ubuntu.com/noble/current/SHA256SUMS -o SHA256SUMS
python3 - <<'PY'
import hashlib,pathlib
expected=next(line.split()[0] for line in pathlib.Path('SHA256SUMS').read_text().splitlines() if line.endswith('noble-server-cloudimg-amd64.img'))
actual=hashlib.sha256(pathlib.Path('ubuntu.img').read_bytes()).hexdigest()
assert actual==expected
pathlib.Path('image-sha256.txt').write_text(actual+'\n')
PY
bash /lab/boot.sh > /lab/qemu.log 2>&1 &
qemu_pid=$!
ssh_options=(-i /lab/id_ed25519 -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10)
ready=false
for attempt in $(seq 1 60); do
  if ! kill -0 "$qemu_pid" 2>/dev/null; then cat /lab/qemu.log >&2; exit 1; fi
  if ssh "${ssh_options[@]}" -p 2222 tester@127.0.0.1 true 2>/dev/null; then ready=true; break; fi
  sleep 5
done
if [[ $ready != true ]]; then echo 'VM SSH readiness failed' >&2; exit 1; fi
scp "${ssh_options[@]}" -P 2222 installer.run protocols-test.py tester@127.0.0.1:/home/tester/
ssh "${ssh_options[@]}" -p 2222 tester@127.0.0.1 'set -e; cloud-init status --wait; uname -a; ! command -v docker; test ! -d /opt/trusttunnel-web; sudo touch /run/tunnel-disposable-install-test; sudo bash /home/tester/installer.run --non-interactive --address 10.0.2.15 --email admin@example.invalid' > /lab/install.log 2>&1 && install_result=0 || install_result=$?
printf '%s\n' "$install_result" > /lab/install.exit
if [[ $install_result -eq 0 ]]; then
  ssh "${ssh_options[@]}" -p 2222 tester@127.0.0.1 'sudo python3 /home/tester/protocols-test.py' > /lab/protocols.log 2>&1 && protocol_result=0 || protocol_result=$?
  printf '%s\n' "$protocol_result" > /lab/protocols.exit
fi
exit "${protocol_result:-$install_result}"
