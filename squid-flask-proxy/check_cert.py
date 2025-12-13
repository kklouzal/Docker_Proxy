import socket, ssl

proxy_host = '127.0.0.1'
proxy_port = 3128
host = 'www.kumadoll.com'
port = 443

sock = socket.create_connection((proxy_host, proxy_port), timeout=10)
req = (f"CONNECT {host}:{port} HTTP/1.1\r\n"
       f"Host: {host}:{port}\r\n"
       "Proxy-Connection: keep-alive\r\n\r\n").encode("ascii")
sock.sendall(req)

resp = b''
while b'\\r\\n\\r\\n' not in resp and len(resp) < 16384:
    chunk = sock.recv(4096)
    if not chunk:
        break
    resp += chunk

status_line = resp.split(b'\\r\\n', 1)[0].decode('iso-8859-1', 'replace')
print('connect_status', status_line)

ctx = ssl._create_unverified_context()
ssock = ctx.wrap_socket(sock, server_hostname=host)
cert = ssock.getpeercert()
issuer = dict(x[0] for x in cert.get('issuer', []))
subject = dict(x[0] for x in cert.get('subject', []))
print('subject_CN', subject.get('commonName'))
print('issuer_CN', issuer.get('commonName'))
ssock.close()
