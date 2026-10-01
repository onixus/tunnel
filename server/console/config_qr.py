"""Render an already-authorized export locally, without changing its payload."""
import base64
import io

# Bound work before QR version fitting. Larger exports remain downloadable intact.
MAX_INPUT_BYTES = 8192
TOO_LARGE = 'Конфигурация не помещается в один QR-код. Скопируйте ссылку или скачайте файл. Данные не сокращены.'
UNAVAILABLE = 'Не удалось создать QR-код. Скопируйте ссылку или скачайте файл.'


def with_qr(result: dict) -> dict:
    """Keep the canonical export intact, even if optional QR rendering fails.

    Do not log the content, SVG, exceptions, or data URI. The caller performs
    admin/CSRF/consent checks and returns this only in a no-store POST response.
    """
    reply = dict(result, qr_data_url=None, qr_error=None)
    content = result.get('content')
    if not isinstance(content, str) or not content:
        reply['qr_error'] = UNAVAILABLE
        return reply
    if len(content) > MAX_INPUT_BYTES:
        reply['qr_error'] = TOO_LARGE
        return reply
    try:
        payload = content.encode('utf-8')
        if len(payload) > MAX_INPUT_BYTES:
            reply['qr_error'] = TOO_LARGE
            return reply
        import qrcode
        from qrcode.exceptions import DataOverflowError
        from qrcode.image.svg import SvgPathFillImage

        qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M,
                           box_size=8, border=4)
        # The scanned bytes must equal the existing export, including TLS data.
        qr.add_data(payload, optimize=0)
        try:
            qr.make(fit=True)
        except (DataOverflowError, ValueError):
            # qrcode 8.2 may report oversized auto-fit as invalid version 41.
            reply['qr_error'] = TOO_LARGE
            return reply
        image = qr.make_image(image_factory=SvgPathFillImage)
        buffer = io.BytesIO()
        image.save(buffer)
        reply['qr_data_url'] = 'data:image/svg+xml;base64,' + base64.b64encode(buffer.getvalue()).decode('ascii')
    except Exception:
        # No exception details: upstream failures may contain credentials.
        reply['qr_error'] = UNAVAILABLE
    return reply
