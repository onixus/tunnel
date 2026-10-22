"""Install portal UI assets into an additive image, preserving overlay navigation."""
from pathlib import Path
import shutil
import sys


def apply(source, target):
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
