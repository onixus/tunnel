"""Install portal UI assets into an additive image, preserving overlay navigation."""
from pathlib import Path
import re
import shutil
import sys

# The modules that render templates. main.py and endpoint.py are patched in deployed
# images (portal_patch.py, install-trusttunnel-routing.py), so they cannot be compared.
RENDERING_MODULES = ('routes_admin.py', 'routes_client.py', 'routes_device.py', 'templating.py')


def check_portal_version(source, target):
    """Templates are tied to the route code that renders them; refuse foreign images."""
    for name in RENDERING_MODULES:
        installed = target / name
        if not installed.is_file() or installed.read_bytes() != (source / name).read_bytes():
            raise RuntimeError(f'Portal {name} differs from server/upstream; rebuild the base image from this checkout')


# Supervisor contract the overlay relies on (fail-closed revocation, standby
# credentials). Checked by marker because endpoint.py is patched in deployed images.
REQUIRED_SUPERVISOR_CONTRACT = 2
SUPERVISOR_MARKERS = (('endpoint.py', re.compile(r'^SUPERVISOR_CONTRACT = (\d+)$', re.M)),
                      ('db.py', re.compile(r'^def claim_credential\(', re.M)))


def check_supervisor(target):
    for name, marker in SUPERVISOR_MARKERS:
        installed = target / name
        found = marker.search(installed.read_text(encoding='utf-8')) if installed.is_file() else None
        if found is None or (found.groups() and int(found.group(1)) < REQUIRED_SUPERVISOR_CONTRACT):
            raise RuntimeError(f'Portal {name} predates the endpoint supervisor contract; rebuild the base image from this checkout')


def apply(source, target):
    check_portal_version(source, target)
    check_supervisor(target)
    client = target / 'templates/base_client.html'
    admin = target / 'templates/base_admin.html'
    profiles = client.exists() and 'href="/profiles"' in client.read_text(encoding='utf-8')
    routes = admin.exists() and 'href="/admin/agent-routes"' in admin.read_text(encoding='utf-8')
    client_html = (source / 'templates/base_client.html').read_text(encoding='utf-8')
    admin_html = (source / 'templates/base_admin.html').read_text(encoding='utf-8')
    if profiles and 'href="/profiles"' not in client_html:
        anchor = '<span class="sp"></span>'
        if client_html.count(anchor) != 1:
            raise RuntimeError('Portal navigation anchor mismatch')
        client_html = client_html.replace(anchor, anchor + '\n  {% if request.cookies.get("user_token") %}<a href="/profiles">Обмен профилями</a>{% endif %}')
    if routes and 'href="/admin/agent-routes"' not in admin_html:
        anchor = '<a href="/admin/settings"'
        if admin_html.count(anchor) != 1:
            raise RuntimeError('Admin navigation anchor mismatch')
        admin_html = admin_html.replace(anchor, '<a href="/admin/agent-routes" class="nav-item">Маршруты устройств</a>\n      ' + anchor)
    for folder in ('templates', 'static'):
        shutil.copytree(source / folder, target / folder, dirs_exist_ok=True)
    client.write_text(client_html, encoding='utf-8')
    admin.write_text(admin_html, encoding='utf-8')


if __name__ == '__main__':
    apply(Path(sys.argv[1]), Path(sys.argv[2]))
