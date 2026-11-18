"""Calls into the owning portal. This sidecar never starts a VPN endpoint itself."""
import hashlib
import hmac
import http.client
import json
from urllib.parse import parse_qs, urlencode, urlsplit

from app import config, security, webauth

# Set by console_app. Acceptance tests retarget that module's PORTAL.
portal_url = None


def _portal():
    if portal_url is None:
        raise RuntimeError('Адрес портала не задан')
    return portal_url()


class PortalRejected(RuntimeError):
    """The portal answered and refused the change. A timeout is not a refusal."""


def _connection(timeout):
    origin = urlsplit(_portal())
    if origin.scheme != 'http' or origin.hostname not in ('trusttunnel-web', '127.0.0.1'):
        raise RuntimeError('Недопустимый внутренний адрес панели')
    return http.client.HTTPConnection(origin.hostname, origin.port or 80, timeout=timeout)


def _admin_cookie(actor_id):
    token = security.create_session_token(str(actor_id), 'admin')
    return webauth.ADMIN_COOKIE + '=' + token, token


def legacy(actor_id, path, data, timeout=30):
    # Fixed paths constructed from checked integer IDs, session never saved in jobs.
    cookie, _ = _admin_cookie(actor_id)
    client = _connection(timeout)
    try:
        client.request('POST', '/admin/' + path, body=urlencode(data),
                       headers={'Cookie': cookie, 'Content-Type': 'application/x-www-form-urlencoded'})
        response = client.getresponse()
        destination = response.getheader('Location', '')
        response.read(1048576)
        query = parse_qs(urlsplit(destination).query)
        if response.status not in (302, 303) or 'err' in query or '/login' in destination:
            raise PortalRejected('Панель TrustTunnel не подтвердила изменение')
    finally:
        client.close()
    return {'message': 'Изменение TrustTunnel применено'}


def managed_device_revoke(actor_id, device_id):
    # The sidecar never starts an endpoint. Use the owning portal supervisor.
    cookie, token = _admin_cookie(actor_id)
    csrf = hmac.new(config.SECRET_KEY.encode(), ('rtrust-admin-routes:' + token).encode(), hashlib.sha256).hexdigest()
    client = _connection(30)
    try:
        client.request('POST', f'/admin/api/device-credentials/{device_id}/revoke',
                       headers={'Cookie': cookie, 'X-CSRF-Token': csrf})
        response = client.getresponse()
        raw = response.read(1048576)
        if response.status != 200:
            raise RuntimeError('Портал не подтвердил отзыв устройства')
        result = json.loads(raw)
        revoke = next((op for op in result.get('operations', []) if op['action'] == 'revoke'), None)
        if revoke and revoke['state'] != 'applied':
            raise RuntimeError('Отзыв записан, но endpoint не подтвердил применение. Повторите операцию после восстановления endpoint.')
        return {'message': 'Отзыв отдельного VPN-пароля применён на endpoint' if revoke else 'Доступ к порталу отозван. Общие и внешние VPN-пароли остаются действующими.'}
    finally:
        client.close()


def portal_status(admin_id):
    """Read the endpoint the portal process owns. This sidecar never starts one."""
    cookie, _ = _admin_cookie(admin_id)
    client = _connection(10)
    try:
        client.request('GET', '/admin/api/endpoint-status', headers={'Cookie': cookie})
        response = client.getresponse()
        raw = response.read(65536)
    finally:
        client.close()
    if response.status != 200:
        raise RuntimeError('Портал не отдал состояние endpoint')
    status = json.loads(raw)
    if not isinstance(status, dict) or type(status.get('running')) is not bool:
        raise RuntimeError('Портал не отдал состояние endpoint')
    domains = status.get('cert_domains')
    return {'running': status['running'], 'domain': status.get('domain') or '', 'cert_present': status.get('cert_present') is True,
            'port': str(status.get('port') or '8443'), 'cert_domains': domains if isinstance(domains, list) else []}
