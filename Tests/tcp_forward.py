#!/usr/bin/env python3
"""Short-lived TCP forwarder used only by the two-VM integration test."""
import select
import socket
import sys
import threading

listen_ip, listen_port, target_ip, target_port, permitted = sys.argv[1:6]
authentication = sys.argv[6:] if len(sys.argv) > 6 else []
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((listen_ip, int(listen_port)))
server.listen(64)
print('forwarder_ready:' + str(server.getsockname()[1]), flush=True)

def handle(client):
    remote = None
    try:
        remote = socket.create_connection((target_ip, int(target_port)), timeout=5)
        client.settimeout(10)
        remote.settimeout(10)
        if authentication:
            def readn(sock, length):
                data = b''
                while len(data) < length:
                    part = sock.recv(length - len(data))
                    if not part: raise OSError('connection closed')
                    data += part
                return data
            version, count = readn(client, 2)
            methods = readn(client, count)
            if version != 5 or 2 not in methods: return
            client.sendall(b'\x05\x02')
            version, length = readn(client, 2)
            username = readn(client, length)
            length = readn(client, 1)[0]
            password = readn(client, length)
            if version != 1 or username != authentication[0].encode() or password != authentication[1].encode():
                client.sendall(b'\x01\x01'); return
            remote.sendall(b'\x05\x01\x00')
            if readn(remote, 2) != b'\x05\x00': return
            client.sendall(b'\x01\x00')
        inputs = [client, remote]
        while inputs:
            ready, _, _ = select.select(inputs, [], [], 60)
            if not ready:
                break
            for source in ready:
                dest = remote if source is client else client
                data = source.recv(32768)
                if not data:
                    inputs.remove(source)
                    try: dest.shutdown(socket.SHUT_WR)
                    except OSError: pass
                else:
                    dest.sendall(data)
    except OSError:
        pass
    finally:
        client.close()
        if remote: remote.close()

while True:
    client, peer = server.accept()
    if peer[0] != permitted:
        client.close()
    else:
        threading.Thread(target=handle, args=(client,), daemon=True).start()
