"""Register the additive exchange integration once, including image upgrades."""
from pathlib import Path


def integrate(root):
    main = root / 'main.py'
    source = main.read_text(encoding='utf-8')
    anchor = 'app.include_router(client_router)'
    if source.count(anchor) != 1:
        raise RuntimeError('Portal router anchor mismatch')
    hook = 'rtrust_profiles.install(app)'
    if hook not in source:
        source = source.replace(anchor, 'from . import rtrust_profiles\n' + hook + '\n' + anchor)
    if source.count(hook) != 1:
        raise RuntimeError('Duplicate profile router registration')
    template = root / 'templates/base_client.html'
    html = template.read_text(encoding='utf-8')
    anchor = '<span class="sp"></span>'
    if html.count(anchor) != 1:
        raise RuntimeError('Portal navigation anchor mismatch')
    if 'href="/profiles"' not in html:
        html = html.replace(anchor, anchor + '\n  {% if request.cookies.get("user_token") %}<a href="/profiles">Обмен профилями</a>{% endif %}')
    admin_template = root / 'templates/base_admin.html'
    admin_html = admin_template.read_text(encoding='utf-8') if admin_template.exists() else None
    if admin_html is not None and 'href="/admin/agent-routes"' not in admin_html:
        admin_anchor = '<a href="/admin/settings"'
        if admin_html.count(admin_anchor) != 1:
            raise RuntimeError('Admin navigation anchor mismatch')
        admin_html = admin_html.replace(admin_anchor, '<a href="/admin/agent-routes" class="nav-item">Маршруты устройств</a>\n      ' + admin_anchor)
    # Validate all anchors before writing any file.
    main.write_text(source, encoding='utf-8')
    template.write_text(html, encoding='utf-8')
    if admin_html is not None: admin_template.write_text(admin_html, encoding='utf-8')


if __name__ == '__main__':
    integrate(Path('/app/app'))
    print('Applied profile API and navigation integration')
