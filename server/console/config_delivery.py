"""Deliver a user's own VPN configuration by e-mail and/or Telegram.

Runs only as an admin-confirmed queued job. Credentials are rendered at execution
time and are never stored in the job payload, result, audit or logs.
"""
import base64
import smtplib
import ssl
import struct
import zlib
from email.message import EmailMessage

CHANNELS = ('email', 'telegram')
TG_TEXT_LIMIT = 3500
INSTRUCTIONS = {
    'hysteria': 'Импортируйте ссылку hysteria2:// в клиент (Hiddify, v2rayN, NekoBox, Streisand) или отсканируйте QR-код.',
    'amnezia': 'Импортируйте файл .conf в AmneziaVPN или AmneziaWG (версия с поддержкой AmneziaWG 3.1) либо отсканируйте QR-код.',
    'trusttunnel': 'Импортируйте ссылку в приложение TrustTunnel / R-TrustTunnel, отсканируйте QR-код или используйте TOML в консольном клиенте.',
}
WARNING = 'Конфигурация содержит данные доступа. Не пересылайте её другим людям.'


class DeliveryError(RuntimeError):
    pass


def qr_png(content, scale=8, border=4):
    """Grayscale PNG without Pillow (absent from the portal image). None if it does not fit."""
    import qrcode
    from qrcode.exceptions import DataOverflowError
    payload = content.encode('utf-8')
    if len(payload) > 2900:
        return None
    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=1, border=border)
    qr.add_data(payload, optimize=0)
    try:
        qr.make(fit=True)
    except (DataOverflowError, ValueError):
        return None
    matrix = qr.get_matrix()
    size = len(matrix) * scale
    raw = bytearray()
    for row in matrix:
        line = bytes(0 if cell else 255 for cell in row for _ in range(scale))
        for _ in range(scale):
            raw += b'\x00' + line

    def chunk(kind, data):
        return struct.pack('>I', len(data)) + kind + data + struct.pack('>I', zlib.crc32(kind + data) & 0xffffffff)
    return (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', size, size, 8, 0, 0, 0, 0))
            + chunk(b'IDAT', zlib.compress(bytes(raw), 9)) + chunk(b'IEND', b''))


def hysteria_bundle(user, export):
    if user.get('deleted'):
        raise DeliveryError('Пользователь Hysteria заблокирован; конфигурация не отправлена')
    link = export({'id': user['id']})['content']
    name = user['username']
    files = [(f'hysteria-{name}.txt', (link + '\n').encode(), 'text/plain')]
    return {'title': 'Hysteria — ' + name, 'kind': 'hysteria', 'items': [{'name': name, 'link': link, 'files': files}]}


def amnezia_bundle(user, export):
    if user.get('deleted'):
        raise DeliveryError('Пользователь AmneziaWG заблокирован; конфигурация не отправлена')
    # AmneziaWG has no link form: the .conf text is what clients import and scan.
    conf = export({'id': user['id']})['content']
    name = user['username']
    files = [(f'amneziawg-{name}.conf', conf.encode(), 'text/plain')]
    return {'title': 'AmneziaWG — ' + name, 'kind': 'amnezia', 'items': [{'name': name, 'link': conf, 'files': files}]}


def trusttunnel_bundle(user):
    from app import conninfo, db
    from app.client_config import build_client_toml
    from app.rtrust_profiles import codec, managed_document
    if user.get('status') != 'active':
        raise DeliveryError('Пользователь TrustTunnel заблокирован; конфигурация не отправлена')
    configs = [c for c in db.list_user_configs(user['id']) if not c['revoked_at']]
    if not configs:
        raise DeliveryError('У пользователя TrustTunnel нет действующих ключей. Сначала выпустите ключ.')
    settings = db.get_settings()
    items = []
    for cfg in configs:
        # Same serializer path as the console export, so links match what admins see.
        link = codec(managed_document(cfg)['content'], 'tt')['content']
        toml = build_client_toml(conninfo.connection_info(cfg, settings))
        name = cfg['label'] or cfg['tt_username']
        items.append({'name': name, 'link': link,
                      'files': [(f'trusttunnel-{cfg["id"]}.toml', toml.encode(), 'application/toml')]})
    return {'title': 'TrustTunnel — ' + user['email'], 'kind': 'trusttunnel', 'items': items}


def body_text(bundle):
    lines = [f'Ваша конфигурация VPN: {bundle["title"]}', '', INSTRUCTIONS[bundle['kind']], WARNING, '']
    for item in bundle['items']:
        lines += [item['name'] + ':', item['link'], '']
    lines.append('QR-коды и файлы конфигурации приложены.')
    return '\n'.join(lines)


def smtp_send(message):
    from app import db, mailer
    host = db.get_setting('smtp_host')
    if not host:
        raise DeliveryError('SMTP не настроен')
    port = int(db.get_setting('smtp_port') or '587')
    tls = (db.get_setting('smtp_tls') or 'starttls').lower()
    user = db.get_setting('smtp_user')
    message['From'] = db.get_setting('smtp_from') or user
    # Same transport rules as app.mailer, which only supports text attachments.
    if tls == 'ssl':
        server = mailer.DNSRelaySMTP(host, port, timeout=15, context=ssl.create_default_context())
    else:
        server = smtplib.SMTP(host, port, timeout=15)
    try:
        if tls == 'starttls':
            server.starttls(context=ssl.create_default_context())
        if user:
            server.login(user, db.get_setting('smtp_password'))
        server.send_message(message)
    finally:
        server.quit()


def send_email(address, bundle):
    msg = EmailMessage()
    msg['To'] = address
    msg['Subject'] = 'Ваша конфигурация VPN: ' + bundle['title']
    msg.set_content(body_text(bundle))
    for index, item in enumerate(bundle['items'], 1):
        png = qr_png(item['link'])
        if png:
            msg.add_attachment(png, maintype='image', subtype='png', filename=f'qr-{index}.png')
        for filename, content, mime in item['files']:
            maintype, subtype = mime.split('/')
            msg.add_attachment(content, maintype=maintype, subtype=subtype, filename=filename)
    smtp_send(msg)


def send_telegram(chat_id, bundle, agent):
    def upload(kind, filename, content, caption=''):
        agent('telegram.file', {'chat_id': chat_id, 'kind': kind, 'filename': filename,
                                'data': base64.b64encode(content).decode('ascii'), 'caption': caption})
    agent('telegram.send', {'chat_id': chat_id,
                            'text': f'Ваша конфигурация VPN: {bundle["title"]}\n\n{INSTRUCTIONS[bundle["kind"]]}\n{WARNING}'})
    for index, item in enumerate(bundle['items'], 1):
        text = item['name'] + ':\n' + item['link']
        if len(text) <= TG_TEXT_LIMIT:
            agent('telegram.send', {'chat_id': chat_id, 'text': text})
        png = qr_png(item['link'])
        if png:
            upload('photo', f'qr-{index}.png', png, item['name'])
        for filename, content, _ in item['files']:
            upload('document', filename, content)


def deliver(bundle, recipients, channels, agent):
    """Returns per-channel status. Never includes addresses' credentials or links."""
    status = {}
    for channel in channels:
        try:
            if channel == 'email':
                send_email(recipients['email'], bundle)
            else:
                send_telegram(recipients['telegram'], bundle, agent)
            status[channel] = 'accepted'
        except Exception:
            # Upstream exceptions may echo message content; keep only the outcome.
            status[channel] = 'failed'
    return status
