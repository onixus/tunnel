"""Browser guards for the portal: signed CSRF on HTML forms and response headers.

JSON APIs keep their own tokens. A form POST must echo the signed cookie; the
console mints the same pair because it already shares the portal secret.
"""
import hmac
import secrets
from hashlib import sha256
from urllib.parse import parse_qs

from starlette.datastructures import MutableHeaders
from starlette.requests import Request
from starlette.responses import HTMLResponse

from . import config

COOKIE = 'portal_csrf'
CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; font-src 'self'; "
    "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; "
    "base-uri 'none'; form-action 'self'"
)
HEADERS = {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
    'Content-Security-Policy': CSP,
}


def mint() -> str:
    raw = secrets.token_urlsafe(32)
    mac = hmac.new(config.SECRET_KEY.encode(), raw.encode(), sha256).hexdigest()
    return raw + '.' + mac


def valid(value: str) -> bool:
    raw, dot, mac = value.partition('.')
    if not raw or not dot or not mac:
        return False
    expected = hmac.new(config.SECRET_KEY.encode(), raw.encode(), sha256).hexdigest()
    return hmac.compare_digest(expected, mac)


def _secure(scope) -> bool:
    if scope.get('scheme') == 'https':
        return True
    for key, value in scope.get('headers') or []:
        if key == b'x-forwarded-proto' and value.split(b',', 1)[0].strip() == b'https':
            return True
    return False


def _cookie(token: str, secure: bool) -> str:
    parts = [f'{COOKIE}={token}', 'Path=/', 'HttpOnly', 'SameSite=Lax', 'Max-Age=86400']
    if secure:
        parts.append('Secure')
    return '; '.join(parts)


class PortalGuards:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get('type') != 'http':
            await self.app(scope, receive, send)
            return
        request = Request(scope, receive)
        token = request.cookies.get(COOKIE, '')
        fresh = not valid(token)
        if fresh:
            token = mint()
        scope.setdefault('state', {})
        scope['state']['csrf'] = token
        method = request.method
        body = await request.body() if method == 'POST' else b''
        if method == 'POST' and _is_form(request.headers.get('content-type', '')):
            sent = _form_csrf(body, request.headers.get('content-type', ''))
            if not sent or not hmac.compare_digest(sent, token):
                await _reject(scope, receive, send, token, fresh, _secure(scope))
                return
        sent_body = False

        async def replay():
            nonlocal sent_body
            if sent_body:
                return {'type': 'http.request', 'body': b'', 'more_body': False}
            sent_body = True
            return {'type': 'http.request', 'body': body, 'more_body': False}

        async def guarded(message):
            if message['type'] == 'http.response.start':
                headers = MutableHeaders(raw=message.setdefault('headers', []))
                for name, value in HEADERS.items():
                    if name.encode().lower() not in {key.lower() for key, _ in headers.raw}:
                        headers[name] = value
                if fresh:
                    headers.append('set-cookie', _cookie(token, _secure(scope)))
            await send(message)

        await self.app(scope, replay if method == 'POST' else receive, guarded)


def _is_form(content_type: str) -> bool:
    return content_type.startswith(('application/x-www-form-urlencoded', 'multipart/form-data'))


def _form_csrf(body: bytes, content_type: str) -> str:
    if content_type.startswith('application/x-www-form-urlencoded'):
        values = parse_qs(body.decode('utf-8', 'replace'), keep_blank_values=True).get('csrf', [''])
        return values[0]
    # No uploaded forms exist. A multipart post still has to carry the field.
    marker = b'name="csrf"'
    at = body.find(marker)
    if at < 0:
        return ''
    rest = body[at + len(marker):]
    end = rest.find(b'\r\n\r\n')
    if end < 0:
        return ''
    value = rest[end + 4:]
    stop = value.find(b'\r\n')
    return value[:stop].decode('utf-8', 'replace') if stop >= 0 else ''


async def _reject(scope, receive, send, token, fresh, secure):
    response = HTMLResponse('Недействительный CSRF-токен', status_code=403)
    if fresh:
        response.set_cookie(COOKIE, token, max_age=86400, httponly=True, samesite='lax', secure=secure, path='/')

    async def drained():
        return {'type': 'http.disconnect'}

    await response(scope, drained, send)
