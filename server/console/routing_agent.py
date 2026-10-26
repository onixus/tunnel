#!/usr/bin/env python3
"""Agent entrypoint adding service routing without changing legacy adapters."""
import json
import os
from pathlib import Path
import socketserver
import threading
from urllib.parse import urlsplit

import agent
import amnezia
import cdn
import protocols
from routing_policy import PolicyError, make_plan
import service_routes


def dispatch(op, data):
    runtime = service_routes.Runtime(agent)
    if op == 'snapshot':
        result = agent.dispatch(op, data)
        try:
            result['routing'] = runtime.snapshot()
        except Exception:
            result['routing'] = {'error': 'Состояние маршрутов недоступно; изменения запрещены'}
        if isinstance(result.get('updates'), dict) and 'error' not in result['updates']:
            result['updates']['upstream'] = protocols.client_releases(agent)
        for key, read in (('protocols', protocols.status), ('amnezia_users', amnezia.users), ('cdn_users', cdn.users)):
            try:
                result[key] = read()
            except PolicyError as exc:
                result[key] = {'error': str(exc)}
            except Exception:
                result[key] = {'error': 'Источник временно недоступен'}
        return result
    if op == 'updates.fetch':
        return protocols.publish_client(data, agent)
    if op.startswith('protocols.'):
        return protocols.dispatch(op, data, agent)
    if op.startswith('cdn.'):
        return cdn.dispatch(op, data)
    if op.startswith('amnezia.'):
        # Clients connect to the same public hostname as the other protocols.
        return amnezia.dispatch(op, data, urlsplit(agent.ORIGIN).hostname)
    if op == 'routes.preview':
        with service_routes.route_lock():
            if service_routes.PENDING.exists():
                raise PolicyError('Предыдущее переключение требует проверки восстановления')
            plan = make_plan(data, runtime.observe())
            # The preview contains only public route IDs and service labels.
            return {k: plan[k] for k in ('changes', 'untouched', 'control_plane', 'revision')}
    if op == 'routes.services':
        return service_routes.apply(runtime, data)
    if op == 'updates.server' and (service_routes.POLICY.exists() or service_routes.TT_CONFIG.exists()):
        raise PolicyError('При сервисной маршрутизации обновление компонентов выполняется оператором с сохранением адаптера; см. service-routing.md')
    if op == 'routes.apply':
        if service_routes.PENDING.exists():
            raise PolicyError('Сначала завершите восстановление предыдущего переключения')
        result = agent.dispatch(op, data)
        # Exception edits target Hysteria ACL; TrustTunnel and CDN routers must follow them.
        try:
            synced = service_routes.sync_exceptions(runtime)
        except PolicyError as exc:
            synced = 'Исключения не синхронизированы: ' + str(exc)
        except Exception:
            synced = 'Исключения не синхронизированы; повторите сохранение исключений или проверьте журнал'
        if synced:
            result['message'] = result.get('message', '') + ' ' + synced
        return result
    return agent.dispatch(op, data)


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.connection.settimeout(600)
        try:
            raw = self.rfile.readline(65537)
            if len(raw) > 65536 or not raw.endswith(b'\n'):
                raise PolicyError('Слишком большой запрос')
            request = json.loads(raw)
            if not isinstance(request, dict) or not isinstance(request.get('op'), str) or not isinstance(request.get('data', {}), dict):
                raise PolicyError('Некорректный запрос')
            if request['op'] in ('snapshot', 'protocols.check'):
                result = dispatch(request['op'], request.get('data', {}))
            else:
                with agent.LOCK:
                    result = dispatch(request['op'], request.get('data', {}))
            response = {'ok': True, 'result': result}
        except (PolicyError, agent.Rejected) as exc:
            response = {'ok': False, 'error': str(exc)}
        except Exception:
            response = {'ok': False, 'error': 'Операция не завершена; проверьте журнал и состояние перед повтором'}
        self.wfile.write(json.dumps(response).encode() + b'\n')


def main():
    os.umask(0o077)
    if service_routes.PENDING.exists():
        # Recover even if the agent died between journalling and arming the timer.
        try:
            pending = json.loads(service_routes.PENDING.read_text())
            service_routes.watchdog_restore(Path(pending['journal']))
        except Exception:
            pass  # Keep reads available; the pending marker blocks all route writes.
    threading.Thread(target=protocols.auto_check, daemon=True).start()
    path = Path(agent.SOCKET)
    path.parent.mkdir(mode=0o750, exist_ok=True)
    path.unlink(missing_ok=True)
    with socketserver.ThreadingUnixStreamServer(agent.SOCKET, Handler) as server:
        os.chown(path.parent, 0, 10001)
        os.chmod(path.parent, 0o750)
        os.chown(path, 0, 10001)
        os.chmod(path, 0o660)
        server.serve_forever()


if __name__ == '__main__':
    main()
