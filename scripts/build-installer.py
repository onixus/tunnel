#!/usr/bin/env python3
"""Package reviewed working-tree sources and an immutable client source snapshot."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
CLIENT_SHA = '4400ca12938619df92326c4abe21818bf39915e9'
# Images the fresh installer would otherwise build or pull on the server.
PORTAL_IMAGE = 'tunnel-fresh-portal:local'
NGINX_IMAGE = 'nginx:1.28-alpine'
IMAGES = 'images/tunnel-images.tar.gz'


def save_images(staging):
    """Build the portal for the server architecture and export it with nginx."""
    platform = ['--platform', 'linux/amd64']
    subprocess.run(['docker', 'buildx', 'build', *platform, '--load', '-f', str(staging / 'deploy/fresh-portal.Dockerfile'),
                    '-t', PORTAL_IMAGE, str(staging)], check=True)
    subprocess.run(['docker', 'pull', *platform, NGINX_IMAGE], check=True)
    target = staging / IMAGES
    target.parent.mkdir()
    with target.open('wb') as out:
        save = subprocess.Popen(['docker', 'save', *platform, PORTAL_IMAGE, NGINX_IMAGE], stdout=subprocess.PIPE)
        subprocess.run(['gzip', '-6'], stdin=save.stdout, stdout=out, check=True)
        if save.wait():
            raise subprocess.CalledProcessError(save.returncode, 'docker save')
    return {'archive': IMAGES, 'sha256': hashlib.sha256(target.read_bytes()).hexdigest(),
            'tags': [PORTAL_IMAGE, NGINX_IMAGE], 'platform': 'linux/amd64'}


def build(client, output, target='ubuntu24', with_images=False):
    subprocess.run(['git', '-C', str(client), 'cat-file', '-e', CLIENT_SHA + '^{commit}'], check=True)
    output.mkdir(parents=True, exist_ok=True)
    basename = 'tunnel-installer-' + target + '-amd64' + ('-images' if with_images else '')
    archive = output / (basename + '.tar.gz')
    hashes = {}
    with tempfile.TemporaryDirectory() as folder:
        staging = Path(folder)
        # Explicit public source roots; never package databases, env files or local results.
        for base in ('server', 'deploy', 'scripts', 'examples', 'docs', 'patches', 'tests', 'ci'):
            for path in (ROOT / base).rglob('*'):
                if not path.is_file() or any(p in ('__pycache__', 'node_modules', '.pytest_cache', 'data', 'certs', 'backups') for p in path.parts):
                    continue
                if path.suffix in ('.pyc', '.db', '.pem', '.key', '.log') or path.name.startswith('.env') or path.name in ('.DS_Store', '.coverage'):
                    continue
                rel = path.relative_to(ROOT)
                destination = staging / rel
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(path.read_bytes()); destination.chmod(path.stat().st_mode & 0o777)
                hashes[str(rel)] = hashlib.sha256(destination.read_bytes()).hexdigest()
        (staging / 'README.md').write_bytes((ROOT / 'README.md').read_bytes())
        hashes['README.md'] = hashlib.sha256((staging / 'README.md').read_bytes()).hexdigest()
        raw = subprocess.check_output(['git', '-C', str(client), 'archive', CLIENT_SHA])
        with tarfile.open(fileobj=io.BytesIO(raw)) as source:
            source.extractall(staging / 'client-source', filter='data')
        images = save_images(staging) if with_images else None
        metadata = {'server_head': subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], text=True).strip(),
                    'working_tree': True, 'target': target, 'client_sha': CLIENT_SHA, 'files_sha256': hashes}
        if images:
            metadata['images'] = images
        (staging / 'manifest.json').write_text(json.dumps(metadata, indent=2))
        (staging / 'START-HERE.txt').write_text((ROOT / ('docs/fresh-install-centos.md' if target == 'centos-stream' else 'docs/fresh-install.md')).read_text())
        with tarfile.open(archive, 'w:gz') as bundle:
            bundle.add(staging, arcname='tunnel-installer')
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    (output / (archive.name + '.sha256')).write_text(digest + '  ' + archive.name + '\n')
    # A single file for first-time operators; the embedded tar is verified before extraction.
    header = '''#!/usr/bin/env bash
set -euo pipefail
if [[ ${EUID} -ne 0 ]]; then echo "Запустите: sudo bash $0" >&2; exit 1; fi
umask 077
export TUNNEL_INSTALL_TARGET=__TARGET__
stage=$(mktemp -d /var/tmp/tunnel-installer.XXXXXX)
trap 'rm -rf -- "$stage"' EXIT
payload_line=$(awk '/^__TUNNEL_PAYLOAD__$/{print NR+1;exit}' "$0")
tail -n +"$payload_line" -- "$0" > "$stage/payload.tar.gz"
printf '%s  %s\\n' '__DIGEST__' "$stage/payload.tar.gz" | sha256sum -c -
tar -xzf "$stage/payload.tar.gz" -C "$stage"
bash "$stage/tunnel-installer/deploy/install.sh" "$@" && result=0 || result=$?
if [[ $result -ne 0 ]]; then echo "После исправления ошибки: sudo bash $0 --resume" >&2; fi
exit "$result"
__TUNNEL_PAYLOAD__
'''.replace('__DIGEST__', digest).replace('__TARGET__', target)
    single = output / (basename + '.run')
    single.write_bytes(header.encode() + archive.read_bytes())
    single.chmod(0o755)
    single_digest = hashlib.sha256(single.read_bytes()).hexdigest()
    (output / (single.name + '.sha256')).write_text(single_digest + '  ' + single.name + '\n')
    print(json.dumps({'installer': str(single.resolve()), 'sha256': single_digest,
                      'archive': str(archive.resolve()), 'bytes': single.stat().st_size}, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--client-source', type=Path, required=True)
    parser.add_argument('--target', choices=('ubuntu24', 'centos-stream'), default='ubuntu24')
    parser.add_argument('--output', type=Path, default=ROOT / 'dist')
    parser.add_argument('--with-images', action='store_true', help='embed prebuilt amd64 portal and nginx images (needs Docker buildx)')
    args = parser.parse_args()
    build(args.client_source, args.output, args.target, args.with_images)
