"""Stand-in for trusttunnel_endpoint with the same reload contract.

Like the official 1.1.0 binary it reads vpn.toml, rules.toml and the
credentials file once at start and re-reads only hosts.toml on SIGHUP.
Line protocol over TCP: the client sends "username password", gets "OK" and
then an echo of every line, or "DENY" and the connection is closed.
"""
import signal
import socket
import sys
import threading
import tomllib
from pathlib import Path


def main():
    vpn = tomllib.loads(Path(sys.argv[1]).read_text())
    tomllib.loads(Path(sys.argv[2]).read_text())
    clients = tomllib.loads(Path(vpn['credentials_file']).read_text()).get('client', [])
    accounts = {(c['username'], c['password']) for c in clients}
    host, port = vpn['listen_address'].rsplit(':', 1)

    def hangup(*_):
        tomllib.loads(Path(sys.argv[2]).read_text())
        with open('sighup.count', 'a') as f:
            f.write('1')
    signal.signal(signal.SIGHUP, hangup)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))

    def serve(conn):
        with conn, conn.makefile('rwb', buffering=0) as stream:
            credentials = tuple(stream.readline().decode().split())
            if credentials not in accounts:
                stream.write(b'DENY\n')
                return
            stream.write(b'OK\n')
            for line in stream:
                stream.write(line)

    listener = socket.create_server(('127.0.0.1', int(port)))
    while True:
        conn, _ = listener.accept()
        threading.Thread(target=serve, args=(conn,), daemon=True).start()


if __name__ == '__main__':
    main()
