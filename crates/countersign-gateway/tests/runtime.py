"""Exercise real Linux Gateway processes against a test-only grant authority and mTLS site,
directly and through a test-only egress proxy.

Usage: python3 crates/countersign-gateway/tests/runtime.py target/debug/countersign-gateway
           [--worker-sandbox namespaces|filter] [--startup-fails LAYER] [--landlock unavailable]
           [--silent-egress-proxy]
Requires libnss-wrapper, curl with HTTPS proxy support, and python-cryptography, and bubblewrap
for the namespace sandbox. --startup-fails is for a host that refuses LAYER of the chosen worker
sandbox: the Gateway has to exit with the error that names the sandbox and that layer.
--landlock unavailable is for a host without Landlock: the Gateway has to start and say so.
--silent-egress-proxy runs only the case of an egress proxy that accepts the CONNECT and never
answers, which ends at the Gateway's 120-second deadline: give it about two minutes more.
No host DNS or trust store modifications.
"""
import base64
import concurrent.futures
import contextlib
import datetime
import hashlib
import http.server
import json
import os
import re
from pathlib import Path
import signal
import socket
import socketserver
import ssl
import subprocess
import sys
import tempfile
import threading
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def identity(directory, name, issuer=None, hosts=()):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    signer, issuer_name = (key, subject) if issuer is None else (issuer[0], issuer[1].subject)
    now = datetime.datetime.now(datetime.timezone.utc)
    ca = issuer is None
    builder = (x509.CertificateBuilder().issuer_name(issuer_name).subject_name(subject)
               .public_key(key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(now - datetime.timedelta(minutes=1))
               .not_valid_after(now + datetime.timedelta(days=1))
               .add_extension(x509.BasicConstraints(ca, 0 if ca else None), critical=True)
               .add_extension(x509.KeyUsage(True, False, False, False, False, ca, ca, False, False), True))
    if not ca:
        usage = ExtendedKeyUsageOID.SERVER_AUTH if hosts else ExtendedKeyUsageOID.CLIENT_AUTH
        builder = builder.add_extension(x509.ExtendedKeyUsage([usage]), False)
    if hosts:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(h) for h in hosts]), False)
    cert = builder.sign(signer, hashes.SHA256())
    path = directory / f'{name}.pem'
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (directory / f'{name}.key').write_bytes(key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return key, cert


def publish_crl(path, ca, serial, deadline):
    key, issuer = ca
    now = datetime.datetime.now(datetime.timezone.utc)
    crl = (x509.CertificateRevocationListBuilder().issuer_name(issuer.subject)
           .last_update(now - datetime.timedelta(seconds=1)).next_update(deadline)
           .add_extension(x509.CRLNumber(serial), False)
           .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), False)
           .sign(key, hashes.SHA256()))
    temporary = path.with_suffix('.tmp')
    temporary.write_bytes(crl.public_bytes(serialization.Encoding.DER))
    temporary.replace(path)


def b64(data):
    return base64.b64encode(data).decode('ascii')


def token(workload):
    # The test authority accepts only these exact, pre-registered tokens.
    body = json.dumps({'aud': 'countersign:gateway:workload', 'binding': workload}).encode()
    return 'fixture.' + base64.urlsafe_b64encode(body).decode().rstrip('=') + '.fixture'


class Counting:
    """A server that records the peer of each connection it accepts, before it reads a byte of it."""

    def counted(self, peer):
        with self.accepted:
            self.peers.append(peer)
            self.accepted.notify_all()

    @property
    def connections(self):
        return len(self.peers)

    def accepted_since(self, seen):
        """The connections the server accepted after its first `seen`, other than a probe of ours. It
        accepts in order, so once it has accepted the probe it has accepted every connection before it."""
        with socket.create_connection(self.server_address[:2], timeout=4) as probe:
            mine = probe.getsockname()
            with self.accepted:
                if not self.accepted.wait_for(lambda: mine in self.peers[seen:], 4):
                    # Only an earlier connection holds up the server's accept.
                    assert self.peers[seen:], 'The probe was not accepted'
                return [peer for peer in self.peers[seen:] if peer != mine]


class Fixture(Counting, http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, handler, tls):
        super().__init__(address, handler)
        self.tls = tls
        self.peers = []
        self.accepted = threading.Condition()

    def get_request(self):
        # Counted before the TLS handshake, so a connection the handshake ends counts too.
        connection, address = self.socket.accept()
        self.counted(address)
        try:
            return self.tls.wrap_socket(connection, server_side=True), address
        except OSError:
            connection.close()
            raise

    def handle_error(self, request, client_address):
        # Cancelling an outstanding poll or forcibly cutting off either TLS leg
        # can reset the fixture socket while the HTTP library is reading it.
        if not isinstance(sys.exc_info()[1], (BrokenPipeError, ConnectionResetError, ssl.SSLEOFError)):
            super().handle_error(request, client_address)


class Site(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        fingerprint = hashlib.sha256(self.connection.getpeercert(binary_form=True)).hexdigest().encode()
        if self.path == '/together':
            # Answered only once another request waits here too.
            try:
                self.server.together.wait()
            except threading.BrokenBarrierError:
                self.send_error(503)
                return
        if self.path == '/slow':
            self.send_response(200)
            self.send_header('content-length', '1000000')
            self.end_headers()
            self.wfile.write(b'x')
            self.server.slow_started.set()
            self.connection.settimeout(25)
            # Any end of the upstream leg counts as cutoff; only a read that
            # times out with the leg still open does not. Why (2026-11-20, #29):
            # under load on an aarch64 host, recv on a leg the Gateway had
            # closed raised BrokenPipeError on 4 of 10 runs.
            try:
                ended = not self.connection.recv(1)
            except TimeoutError:
                ended = False
            except OSError:  # ssl.SSLError is an OSError too
                ended = True
            if ended:
                self.server.cutoff.set()
            return
        self.send_response(200)
        self.send_header('content-length', str(len(fingerprint)))
        self.end_headers()
        self.wfile.write(fingerprint)

    def log_message(self, *args):
        pass


class Broker(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        authority = self.server
        token = self.headers.get('Authorization', '').removeprefix('Bearer ')
        if token not in authority.accounts or not self.headers.get('X-Countersign-Gateway-Instance'):
            self.send_error(403)
            return
        user, key, grants = authority.accounts[token]
        if authority.shared and self.headers.get('X-Countersign-Gateway') != authority.service_secret:
            self.send_error(403)
            return
        frame = json.loads(self.rfile.read(int(self.headers['content-length'])))
        body = frame['body']
        now = int(time.time() * 1000)
        msg = frame['type']
        if msg == 'sign':
            # Every signature it is asked for, granted or not.
            authority.signatures.append(body['binding']['host'])
        # One grant for each destination the user can reach.
        grant = grants.get(body.get('host') or body.get('binding', {}).get('host'))
        if msg in ('connect', 'lookup') and grant and body['workload'] == grant['workload']:
            kind = 'activate'
            value = {'activation': {'grant': grant, 'offer': user, 'approval': user,
                                     'expires_at_ms': authority.expires_at},
                     'chain': [authority.public[user]]}
        elif msg == 'watch' and body in grants.values():
            retired = authority.retired[user].wait(5)
            kind, value = ('retire' if retired else 'no_change'), body
        elif msg == 'observed' and grant and body['grant'] == grant:
            kind = 'observed'
            value = body
            with authority.observation_change:
                received = authority.observations.setdefault((user,body['tls_connection']),set())
                received.add(body['observation'])
                authority.observation_change.notify_all()
        elif msg == 'renew_lease' and body['grant'] in grants.values():
            kind = 'lease'
            budget = 2000 if user == 'alice' else 30000
            value = {'binding': body, 'disposition': {'granted': {'budget_ms': budget, 'valid_until_ms': now + budget}}}
        elif msg == 'sign' and grant and body['binding']['grant'] == grant:
            assert body['tls'] == 'tls13' and body['scheme'] == 'ecdsa_nistp256_sha256'
            transcript = base64.b64decode(body['certificate_verify'], validate=True)
            assert transcript.startswith(b' ' * 64 + b'TLS 1.3, client CertificateVerify\x00')
            kind = 'signed'
            value = {'binding': body['binding'], 'signature': b64(key.sign(transcript, ec.ECDSA(hashes.SHA256())))}
        else:
            self.send_error(403)
            return
        reply = json.dumps({'version': 1, 'request_id': frame['request_id'], 'type': kind, 'body': value}).encode()
        self.send_response(200)
        self.send_header('content-length', str(len(reply)))
        self.end_headers()
        self.wfile.write(reply)

    def log_message(self, *args):
        pass


@contextlib.contextmanager
def server(addr, handler, tls):
    httpd = Fixture((addr, 0), handler, tls)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield httpd
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join()


# Like Squid's, each refusal carries a page of the proxy's own. A Workload never sees it.
PAGE = b'<html>test egress proxy error page</html>\n'
ERROR_PAGE = b'content-type: text/html\r\ncontent-length: %d\r\n\r\n%s' % (len(PAGE), PAGE)


# Names whose proxied leg fails, one for each way: the test-only egress proxy refuses, closes
# unanswered, answers with something that is not HTTP, cannot reach the site, or tunnels to a
# site whose certificate is for another name or chains to roots other than the rule's. For
# `banner`, `stub` and `lf` it answers and then keeps the connection open: a line that is not
# HTTP, a few bytes that are not, and a refusal whose lines end in a bare LF. For `silent` it
# reads the CONNECT and never answers.
PROXY_FAILURES = ['refused', 'closed', 'garbled', 'banner', 'stub', 'lf', 'unreachable', 'wrong',
                  'untrusted', 'silent']

# The proxy environment variables the Gateway must never read.
PROXY_VARIABLES = ('HTTPS_PROXY', 'https_proxy', 'HTTP_PROXY', 'http_proxy', 'ALL_PROXY', 'all_proxy')


class KeptOpen(bytes):
    """An answer after which the test-only egress proxy keeps the connection open until the
    Gateway closes it."""


class Tunnel(socketserver.BaseRequestHandler):
    """One CONNECT through the test-only egress proxy. Like Squid, it ends both legs when either ends."""

    def handle(self):
        head = b''
        while b'\r\n\r\n' not in head:
            data = self.request.recv(4096)
            if not data or len(head) > 8192:
                return
            head += data
        line = head.split(b'\r\n', 1)[0].decode('latin-1')
        with self.server.recorded:
            self.server.requests.append(line)
        method, target, _ = (line.split(' ', 2) + ['', ''])[:3]
        host, _, port = target.rpartition(':')
        address = self.server.names.get(host)
        if method != 'CONNECT' or address is None:
            self.request.sendall(b'HTTP/1.1 403 Forbidden\r\n' + ERROR_PAGE)
            return
        if isinstance(address, bytes):
            # This answer and no other, then the end of the connection: the proxy's, or for an
            # answer kept open, the Gateway's.
            self.request.sendall(address)
            if isinstance(address, KeptOpen):
                with contextlib.suppress(OSError):
                    self.request.recv(1)
            return
        try:
            site = socket.create_connection(address if isinstance(address, tuple) else (address, int(port)),
                                            timeout=5)
        except OSError:
            self.request.sendall(b'HTTP/1.1 503 Service Unavailable\r\n' + ERROR_PAGE)
            return
        with site:
            site.settimeout(None)
            self.request.sendall(b'HTTP/1.1 200 Connection established\r\n\r\n')
            def pump(source, sink):
                with contextlib.suppress(OSError):
                    while data := source.recv(65536):
                        sink.sendall(data)
                for leg in (source, sink):
                    with contextlib.suppress(OSError):
                        leg.shutdown(socket.SHUT_RDWR)
            back = threading.Thread(target=pump, args=(site, self.request), daemon=True)
            back.start()
            pump(self.request, site)
            back.join()


class EgressProxy(Counting, socketserver.ThreadingTCPServer):
    """A test-only egress proxy. It records each request line, and is the only resolver of `names`.
    A name it maps to bytes gets those bytes as its whole answer, and one it maps to an address and
    port is tunneled there, whatever port the CONNECT names."""
    daemon_threads = True

    def __init__(self, names):
        super().__init__(('127.0.0.1', 0), Tunnel)
        self.names = names
        self.requests = []
        self.recorded = threading.Lock()
        self.peers = []
        self.accepted = threading.Condition()

    def get_request(self):
        request, peer = super().get_request()
        self.counted(peer)
        return request, peer

    def take(self):
        with self.recorded:
            requests, self.requests = self.requests, []
        return requests


@contextlib.contextmanager
def egress_proxy(names):
    proxy = EgressProxy(names)
    thread = threading.Thread(target=proxy.serve_forever, daemon=True)
    thread.start()
    try:
        yield proxy
    finally:
        proxy.shutdown()
        proxy.server_close()
        thread.join()


def startup_failure(binary, config, sandbox, layer):
    """A host that refuses the chosen worker sandbox stops the Gateway at startup."""
    other = {'namespaces': 'filter', 'filter': 'namespaces'}[sandbox]
    result = subprocess.run([binary, 'serve', str(config)], capture_output=True, text=True, timeout=20)
    sys.stderr.write(result.stderr)
    assert result.returncode != 0, 'The Gateway started under a worker sandbox this host was expected to refuse'
    assert not result.stdout, result.stdout
    lines = result.stderr.splitlines()
    assert len(lines) == 2, lines
    # The sandbox, the layer that failed, then the cause.
    assert re.fullmatch(rf'worker sandbox "{sandbox}" failed: {re.escape(layer)}: \S.*', lines[0]), lines
    assert 'operate/#choose-a-worker-sandbox' in lines[1], lines
    # Neither a fallback nor a hint at one: the other value is never named.
    assert f'"{other}"' not in result.stderr, lines


def configuration_loading(dir, binary, config):
    """`worker_sandbox` is optional and takes two values. Anything else fails loading."""
    path = dir / 'worker-sandbox.json'
    without = {key: value for key, value in config.items() if key != 'worker_sandbox'}
    def loads(**field):
        path.write_text(json.dumps({**without, **field}))
        return subprocess.run([binary, 'env', str(path)], capture_output=True, timeout=10).returncode == 0
    assert loads()
    for value in ('namespaces', 'filter'):
        assert loads(worker_sandbox=value), value
    for value in ('seccomp', 'Filter', 'none', '', None, True, ['filter']):
        assert not loads(worker_sandbox=value), value


def egress_configuration(dir, binary, config):
    """`egress_proxy` is optional: an http URL with a host and a port. `env` and `serve` refuse
    the same configurations, and say why."""
    path = dir / 'egress.json'
    base = {key: value for key, value in config['destinations'][0].items() if key != 'egress'}
    rule = {key: value for key, value in base.items() if key != 'private_networks'}
    def write(proxy, **fields):
        changed = {**config, 'destinations': [{**rule, **fields}]}
        if proxy is not None:
            changed['egress_proxy'] = proxy
        path.write_text(json.dumps(changed))
    def loads(proxy=None, **fields):
        write(proxy, **fields)
        return subprocess.run([binary, 'env', str(path)], capture_output=True, timeout=10).returncode == 0
    def refuses():
        # Both commands, and the same words from each: one line that names the cause.
        results = [subprocess.run([binary, verb, str(path)], capture_output=True, text=True, timeout=10)
                   for verb in ('env', 'serve')]
        for result in results:
            assert result.returncode != 0 and not result.stdout, (path.read_text(), result)
        assert results[0].stderr == results[1].stderr, results
        lines = results[0].stderr.splitlines()
        assert len(lines) == 1, lines
        return lines[0]
    def refused(proxy=None, **fields):
        write(proxy, **fields)
        return refuses()
    for proxy in ('http://proxy.test:3128', 'http://127.0.0.1:3128', 'http://[::1]:3128', 'http://proxy.test:3128/'):
        assert loads(proxy), proxy
    error = refused('https://proxy.test:3128')
    assert 'egress_proxy' in error and 'https' in error, error
    for proxy in ('http://user:secret@proxy.test:3128', 'http://user@proxy.test:3128'):
        error = refused(proxy)
        assert 'egress_proxy' in error and 'credentials' in error and 'secret' not in error, error
    for proxy in ('http://proxy.test', 'http://proxy.test:', 'http://proxy.test:0', 'http://[::1]', 'http://proxy.test:3128/path', 'http://proxy.test:3128?q', 'ftp://proxy.test:3128',
                  'proxy.test:3128', ''):
        assert 'egress_proxy' in refused(proxy), proxy
    refused(3128)
    # `env` runs the destination checks `serve` runs, so the launcher meets a bad rule first. And
    # the startup line, which names the destinations that leave their address policy to the egress
    # proxy, is not printed for destinations that fail their checks.
    wildcard = {**base, 'id': 'wild', 'pattern': '*.' + base['pattern'].split('.', 1)[1], 'egress': 'direct'}
    path.write_text(json.dumps({**config, 'egress_proxy': 'http://proxy.test:3128', 'destinations': [rule, wildcard]}))
    error = refuses()
    assert 'exact host and prefix' in error, error
    # A rule's `egress` takes one value, with or without an egress proxy.
    direct = {**base, 'egress': 'direct'}
    assert loads(**direct) and loads('http://proxy.test:3128', **direct)
    # Nobody checks `private_networks` on a proxied route, so a rule may not claim it.
    error = refused('http://proxy.test:3128', **base)
    assert re.search(r'\bsite\b', error) and 'private_networks' in error, error
    assert 'remove' in error and '"egress": "direct"' in error, error
    # Every private rule decides its route, not only the first: one after a proxied rule stops
    # startup too, and the error names it.
    second = {**base, 'id': 'second', 'pattern': 'second.' + base['pattern']}
    path.write_text(json.dumps({**config, 'egress_proxy': 'http://proxy.test:3128', 'destinations': [rule, second]}))
    error = refuses()
    assert re.search(r'\bsecond\b', error) and 'private_networks' in error, error
    for value in ('proxy', 'default', 'Direct', 'none', '', None, True, ['direct']):
        refused('http://proxy.test:3128', egress=value)
        refused(egress=value)


def do_test(dir, binary, ip,site, broker, identities, ca, shared, filter_kill=False, sandbox=None,
            startup_fails=None, landlock=None, egress=None, ignored=None, unusable=None, silent=False):
    """With `egress`, a test-only egress proxy, the Gateway reaches the site only through it. With
    `ignored` instead, the Gateway's environment names that proxy, and the Gateway connects directly.
    With `unusable` as well as `egress`, configuration that leaves the Gateway no usable egress proxy,
    the Gateway can resolve and reach the site itself, and must not. With `silent` as well as
    `egress`, only the case of an egress proxy that never answers runs."""
    host = f'site.test:{site.server_port}'
    # The site again, under a name with a direct route beside the egress proxy.
    direct = f'direct.test:{site.server_port}'
    # Destinations the Gateway and the grant authority allow, whose proxied leg fails.
    failing = {name: f'{name}.test:{site.server_port}' for name in PROXY_FAILURES}
    # Under a wildcard rule, through the egress proxy.
    wild = f'a.wild.test:{site.server_port}'
    # Allowed at the grant authority but not at the Gateway, and the other way round.
    unlisted = f'unlisted.test:{site.server_port}'
    ungranted = f'ungranted.test:{site.server_port}'
    broker.accounts = {}
    broker.retired = {user: threading.Event() for user in identities}
    broker.public = {}
    broker.observations = {}
    broker.signatures = []
    broker.observation_change = threading.Condition()
    broker.shared = shared
    broker.service_secret = 'secret-' * 8
    broker.expires_at = int(time.time()*1000) + 90000
    (dir/'service').write_text(broker.service_secret)
    bindings = {}
    for user, (key, cert) in identities.items():
        principal = 'alice' if user == 'alice-other-context' else user
        workload = {'integrator':'local','user':principal,'context':user,'workload':user,'workload_generation':1}
        der = cert.public_bytes(serialization.Encoding.DER)
        def grant(name, entry, pattern):
            return {'workload':workload,'grant':name,'grant_version':1,'worker':name,'worker_generation':1,
                    'scope':{'entry_id':entry,'entry_version':1,'pattern':pattern},
                    'device':{'pairing':user,'key':user,'channel_generation':1},
                    'cert_sha256':b64(hashlib.sha256(der).digest())}
        bindings[user] = workload
        broker.public[user] = b64(der)
        broker.accounts[token(workload)] = (user,key,{host: grant(user, 'site', host),
                                                      direct: grant(user+'-direct', 'direct', direct),
                                                      # A wildcard rule approves one exact host at a time.
                                                      wild: grant(user+'-wild', 'wild', wild),
                                                      unlisted: grant(user+'-unlisted', 'unlisted', unlisted),
                                                      **{to: grant(f'{user}-{name}', name, to)
                                                         for name, to in failing.items()}})
    with socket.socket() as tmp:
        tmp.bind(('127.0.0.1',0))
        port = tmp.getsockname()[1]
    pub = dir / ('ca.pem' if shared else 'public.pem')
    proxy = ('https' if shared else 'http') + f'://localhost:{port}'
    config = {'listen':f'127.0.0.1:{port}', 'proxy_url':proxy,'ca_output':str(pub),
              'broker_url':f'https://localhost:{broker.server_port}', 'broker_ca':str(dir/'ca.pem'),
              'clock_uncertainty_ms':100,
              'destinations':[{'id':'site','version':1,'pattern':host,'roots':str(dir/'ca.pem'),'private_networks':[ip+'/32']}]}
    if egress:
        # The site's rule leaves its address policy to the egress proxy. The
        # other keeps its own, on a direct route. Only the Gateway's hosts file
        # resolves the egress proxy's name.
        config['egress_proxy'] = f'http://proxy.test:{egress.server_address[1]}'
        del config['destinations'][0]['private_networks']
        proxied = config['destinations'][0]
        config['destinations'].append({**proxied, 'id':'direct', 'pattern':direct,
                                       'private_networks':[ip+'/32'], 'egress':'direct'})
        config['destinations'] += [{**proxied, 'id':name, 'pattern':to} for name, to in failing.items()]
        # The site's certificate does not chain to this rule's roots.
        next(rule for rule in config['destinations'] if rule['id'] == 'untrusted')['roots'] = str(dir/'other-ca.pem')
        config['destinations'] += [{**proxied, 'id':'wild', 'pattern':f'*.wild.test:{site.server_port}'},
                                   {**proxied, 'id':'ungranted', 'pattern':ungranted}]
        config.update(unusable or {})
    if shared:
        crl = dir / 'site.crl'
        publish_crl(crl, ca, 1, datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5))
        for rule in config['destinations']:
            rule['revocation'] = {'kind':'crl', 'files':[str(crl)]}
        config['shared']={'listener_cert':str(dir/'listener.pem'),'listener_key':str(dir/'listener.key'),
                          'gateway_token':str(dir/'service'),
                          'ca':{'type':'local','cert':str(dir/'ca.pem'),'key':str(dir/'ca.key')}}
    else:
        (dir/'sidecar.token').write_text(token(bindings['alice']))
        config.update(workload=bindings['alice'],workload_token=str(dir/'sidecar.token'))
    if sandbox:
        config['worker_sandbox'] = sandbox
    if shared and not egress and not filter_kill:
        # Without an egress proxy, `"egress": "direct"` changes nothing: the
        # sidecar pass runs without it, this one with it.
        config['destinations'][0]['egress'] = 'direct'
    (dir/'config.json').write_text(json.dumps(config))
    if startup_fails:
        return startup_failure(binary, dir/'config.json', sandbox or 'namespaces', startup_fails)
    if not egress:
        configuration_loading(dir, binary, config)
        egress_configuration(dir, binary, config)
    hosts = dir/'hosts'
    def write_hosts(proxy='127.0.0.1'):
        previous = hosts.stat().st_mtime if hosts.exists() else 0
        # Behind the egress proxy only the proxy can resolve the site's name.
        hosts.write_text('127.0.0.1 localhost\n' + (ip+' direct.test\n'+proxy+' proxy.test\n' if egress else '')
                         + ('' if egress and not unusable else ip+' site.test\n'))
        # nss_wrapper rereads the file only when its modification time changes, to the second.
        stamp = max(previous + 2, time.time())
        os.utime(hosts, (stamp, stamp))
    write_hosts()
    # Override /etc/hosts only for the Gateway parent. Grant workers are then
    # isolated by the production launcher and receive only preconnected streams.
    library = os.environ.get('NSS_WRAPPER_LIBRARY') or str(next(Path('/usr/lib').glob('*/libnss_wrapper.so')))
    environment = {**os.environ,'LD_PRELOAD':library,'NSS_WRAPPER_HOSTS':str(hosts)}
    if ignored:
        # Only `egress_proxy` chooses the route, never the environment.
        environment.update({name: f'http://localhost:{ignored.server_address[1]}' for name in PROXY_VARIABLES})
        ignored.take()
    elif egress:
        # Nor does the environment override `egress_proxy`: these name an address where nothing
        # listens, so a Gateway that read them would fail every request.
        with socket.socket() as tmp:
            tmp.bind(('127.0.0.1', 0))
            dead = tmp.getsockname()[1]
        environment.update({name: f'http://127.0.0.1:{dead}' for name in PROXY_VARIABLES})
    if egress:
        resolved = subprocess.run(['getent','ahosts','site.test'], env=environment, capture_output=True, timeout=10)
        if unusable:
            assert resolved.returncode == 0 and ip in resolved.stdout.decode(), ('The Gateway could not reach the site', resolved)
        else:
            assert resolved.returncode == 2, ('The Gateway could resolve the site itself', resolved)
        egress.take()
    with subprocess.Popen([binary,'serve',str(dir/'config.json')], stderr=subprocess.PIPE, text=True,
                          env=environment) as child:
        log = []
        logged = threading.Condition()
        def follow():
            for line in child.stderr:
                sys.stderr.write(line)
                with logged:
                    log.append(line.rstrip('\n'))
                    logged.notify_all()
        threading.Thread(target=follow, daemon=True).start()
        def wait_for_log(pattern, timeout=4):
            with logged:
                return logged.wait_for(lambda: any(re.fullmatch(pattern, line) for line in log), timeout)
        def alive(pid):
            # A killed process stays listed until its new parent collects it.
            try:
                return Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()[0] != 'Z'
            except FileNotFoundError:
                return False
        def descendants(pid):
            child_list = Path(f'/proc/{pid}/task/{pid}/children')
            direct = [int(c) for c in child_list.read_text().split()]
            return direct + [p for c in direct for p in descendants(c)]
        try:
            for _ in range(100):
                if child.poll() is not None:
                    raise RuntimeError(f'Gateway exited {child.returncode}')
                try:
                    with socket.create_connection(('127.0.0.1',port),timeout=.2):
                        break
                except OSError:
                    threading.Event().wait(.05)
            else:
                raise RuntimeError('Gateway did not start')
            # Startup names the worker sandbox and every layer its probe worker applied.
            assert wait_for_log(('Gateway worker sandbox "filter": ' if sandbox == 'filter' else
                                 'Gateway worker sandbox "namespaces": namespaces, ') + 'non-dumpable, '
                                + ('Landlock unavailable' if landlock == 'unavailable' else
                                   r'Landlock (ABI v[1-9]\d*|unavailable)') + ', seccomp allow-list'), log
            if egress:
                # Startup names the egress proxy, and the rules whose address policy it now carries.
                assert wait_for_log(rf'Gateway egress proxy {re.escape(config["egress_proxy"].removeprefix("http://"))} '
                                    r'carries the address policy of destinations: '
                                    + ', '.join(['site', *failing, 'wild', 'ungranted'])), log
            def request(user,extra=(),path='/', timeout=8, to=host):
                args=['curl','--silent','--show-error','--fail','--max-time',str(timeout),'--noproxy','','--proxy',proxy,
                      '--proxy-cacert',str(dir/'ca.pem'),'--cacert',str(pub)]
                if shared:
                    args+=['--proxy-header','Proxy-Authorization: Bearer '+token(bindings[user])]
                return subprocess.run(args + list(extra) + ['https://'+to+path], capture_output=True, timeout=timeout+2)
            def connect(user, to, timeout=8):
                """The Gateway's whole answer to one Workload CONNECT, as bytes."""
                listener = socket.create_connection(('127.0.0.1', port), timeout=timeout)
                if shared:
                    # As curl does, without Python's stricter X.509 profile.
                    trust = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    trust.load_verify_locations(dir/'ca.pem')
                    listener = trust.wrap_socket(listener, server_hostname='localhost')
                lines = [f'CONNECT {to} HTTP/1.1', f'Host: {to}', 'Connection: close']
                if shared:
                    lines.append('Proxy-Authorization: Bearer ' + token(bindings[user]))
                with listener:
                    listener.sendall(('\r\n'.join(lines) + '\r\n\r\n').encode())
                    answer = b''
                    while data := listener.recv(65536):
                        answer += data
                return answer
            def fails_through_egress(to, error, timeout=8):
                """The proxied leg to `to` fails: the Workload reads why, and the site sees nothing."""
                seen = site.connections
                answer = connect(users[0], to, timeout)
                # Never a direct connection instead.
                assert not site.accepted_since(seen), (to, 'The site saw a connection', answer)
                head, _, body = answer.partition(b'\r\n\r\n')
                status, *fields = head.decode('latin-1').split('\r\n')
                headers = {key.lower(): value for key, _, value in (f.partition(': ') for f in fields)}
                assert status.startswith('HTTP/1.1 502 '), (to, answer)
                assert headers.get('countersign-error') == error, (to, answer)
                request_id = headers.get('countersign-request-id')
                assert request_id, (to, answer)
                # Nothing of the egress proxy's own answer reaches the Workload.
                assert body == b'' and b'egress proxy' not in answer, (to, answer)
                assert wait_for_log(rf'Gateway CONNECT {re.escape(request_id)} {error}'), (to, log)
            def refused_before_egress(to):
                """Countersign refuses `to` itself: neither the egress proxy nor the site sees a connection."""
                seen_site, seen_proxy = site.connections, egress.connections
                answer = connect(users[0], to)
                assert answer.startswith(b'HTTP/1.1 403 '), (to, answer)
                assert not egress.accepted_since(seen_proxy), (to, 'The egress proxy saw a connection', answer)
                assert not site.accepted_since(seen_site), (to, 'The site saw a connection', answer)
            users = list(identities) if shared else ['alice']
            if silent:
                # The egress proxy reads the CONNECT and never answers. The Workload reads why when
                # the Gateway's deadline for the CONNECT passes, and the site sees nothing.
                fails_through_egress(failing['silent'], 'proxy_unavailable', timeout=130)
                assert egress.take() == [f'CONNECT {failing["silent"]} HTTP/1.1']
                return
            if unusable:
                seen = egress.connections
                fails_through_egress(host, 'proxy_unavailable')
                assert not egress.accepted_since(seen), 'The egress proxy saw a connection'
                assert egress.take() == []
                return
            def launched_directly():
                # The filter sandbox starts each grant worker itself: every process
                # under the Gateway runs the Gateway's executable, started by the Gateway.
                workers = descendants(child.pid)
                assert workers, 'grant worker missing'
                for pid in workers:
                    status = Path(f'/proc/{pid}/status').read_text()
                    assert re.search(rf'^PPid:\t{child.pid}$', status, re.M), status
                    assert re.search(r'^Name:\tcountersign-gat', status, re.M), status
            if filter_kill:
                # Only Alice's grant worker runs. A grant worker the allow-list
                # kills dies of SIGSYS, so deliver that signal to it: the
                # supervisor cannot tell the two apart.
                first = request('alice')
                assert first.returncode == 0, first.stderr
                if sandbox == 'filter':
                    launched_directly()
                leaves = [pid for pid in descendants(child.pid) if not descendants(pid)]
                assert len(leaves) == 1, leaves
                os.kill(leaves[0], signal.SIGSYS)
                assert wait_for_log(r"Gateway grant alice: grant worker killed by the worker sandbox's filter \(SIGSYS\); "
                                    r'grant fenced'), log
                assert request('alice').returncode != 0, 'A grant whose worker the filter killed was served again'
                assert request('bob').returncode == 0, "Alice's killed grant worker affected Bob"
                # A fresh approval is a new grant, which gets a new grant worker.
                broker.accounts[token(bindings['alice'])][2][host].update(grant='alice-approved-again')
                assert request('alice').returncode == 0, 'A fresh approval did not restore service'
                # No grant worker outlives its supervisor, however the supervisor ends.
                workers = descendants(child.pid)
                assert len(workers) >= 2, workers
                child.kill()
                for _ in range(40):
                    if not any(alive(pid) for pid in workers):
                        break
                    threading.Event().wait(.05)
                else:
                    raise AssertionError('A grant worker outlived its supervisor')
                return
            with concurrent.futures.ThreadPoolExecutor(max_workers=len(users)) as pool:
                results = list(pool.map(request,users))
            for user,res in zip(users,results):
                assert res.returncode==0,(user,res.stderr)
                expected=identities[user][1].fingerprint(hashes.SHA256()).hex().encode()
                assert res.stdout==expected,(user,res.stdout)
            through_egress = [f'CONNECT {host} HTTP/1.1'] * len(users)
            if egress:
                # Each Workload CONNECT opened its own tunnel, named by the site's hostname and port.
                assert egress.take() == through_egress, through_egress
                # The same Gateway reaches the rule with `"egress": "direct"` on its own.
                for user in users:
                    res = request(user, to=direct)
                    assert res.returncode == 0, (user, res.stderr)
                    assert res.stdout == identities[user][1].fingerprint(hashes.SHA256()).hex().encode()
                assert egress.take() == [], 'A direct destination went through the egress proxy'
                # A wildcard rule reaches a host under it that the egress proxy allows.
                for user in users:
                    res = request(user, to=wild)
                    assert res.returncode == 0, (user, res.stderr)
                    assert res.stdout == identities[user][1].fingerprint(hashes.SHA256()).hex().encode()
                assert egress.take() == [f'CONNECT {wild} HTTP/1.1'] * len(users)
                # The egress proxy allows these names, but Countersign does not: one has no rule at
                # the Gateway, the other no grant at the grant authority.
                refused_before_egress(unlisted)
                refused_before_egress(ungranted)
                assert egress.take() == []
                # The egress proxy's name is resolved on every connection. Moved to an address where
                # nothing listens, the next CONNECT fails there; moved back, it succeeds.
                write_hosts(proxy='127.0.0.2')
                fails_through_egress(host, 'proxy_unavailable')
                write_hosts()
                res = request(users[0])
                assert res.returncode == 0, ('The Gateway did not follow the egress proxy back', res.stderr)
                assert egress.take() == [f'CONNECT {host} HTTP/1.1']
                # The egress proxy refuses a name it does not allow.
                fails_through_egress(failing['refused'], 'proxy_denied')
                assert egress.take() == [f'CONNECT {failing["refused"]} HTTP/1.1'], 'The refusal was not the proxy\'s'
                # It closes the connection unanswered, or answers with something that is not HTTP.
                fails_through_egress(failing['closed'], 'proxy_unavailable')
                fails_through_egress(failing['garbled'], 'proxy_unavailable')
                assert egress.take() == [f'CONNECT {failing[name]} HTTP/1.1' for name in ('closed', 'garbled')]
                # It answers and keeps the connection open. The Workload reads why at once, inside
                # `connect`'s timeout, never at the Gateway's 120-second deadline.
                fails_through_egress(failing['banner'], 'proxy_unavailable')
                fails_through_egress(failing['stub'], 'proxy_unavailable')
                fails_through_egress(failing['lf'], 'proxy_denied')
                assert egress.take() == [f'CONNECT {failing[name]} HTTP/1.1' for name in ('banner', 'stub', 'lf')]
                # It cannot reach the site, and says so as Squid does, with a 5xx answer.
                fails_through_egress(failing['unreachable'], 'upstream_failure')
                assert egress.take() == [f'CONNECT {failing["unreachable"]} HTTP/1.1']
                # Through a tunnel it allows, to a site whose certificate is for another name, or
                # does not chain to the rule's roots, the request fails before the user's
                # certificate signs anything.
                for name in ('wrong', 'untrusted'):
                    res = request(users[0], to=failing[name])
                    assert res.returncode != 0 and not res.stdout, (name, res.returncode, res.stdout)
                    assert egress.take() == [f'CONNECT {failing[name]} HTTP/1.1'], (name, 'The egress proxy refused the tunnel')
                    assert failing[name] not in broker.signatures, (name, 'A site with the wrong certificate got a signature')
                assert host in broker.signatures, 'The grant authority recorded no signature at all'
            if ignored:
                assert ignored.take() == [], 'The Gateway took the egress proxy from its environment'
                with logged:
                    assert not any(line.startswith('Gateway egress proxy') for line in log), log
            # One grant worker serves two of its user's connections at once: the
            # site answers neither until both have reached it.
            site.together = threading.Barrier(2, timeout=4)
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                both = list(pool.map(lambda _: request(users[0], path='/together'), range(2)))
            assert all(res.returncode == 0 for res in both), [res.stderr for res in both]
            if sandbox == 'filter':
                launched_directly()
            expected_events = {'mtls_accepted','ingress_closed','egress_closed'}
            with broker.observation_change:
                for user in users:
                    assert broker.observation_change.wait_for(
                        lambda: any(owner == user and events == expected_events
                                    for (owner, _), events in broker.observations.items()), timeout=4
                    ), (user, broker.observations)
            res=request(users[0],['-H','Host: forbidden.test'])
            assert res.returncode!=0, res.stdout
            site.cutoff = threading.Event()
            site.slow_started = threading.Event()
            begin = time.monotonic()
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(request,'alice',(),'/slow')
                assert site.slow_started.wait(4), 'TLS connection did not reach site'
                if not shared:
                    # The only grant belongs to Alice. Stop all of this launcher's
                    # descendants, including the worker. Both network relays must
                    # still enforce cutoff, without help from any child process.
                    workers = descendants(child.pid)
                    assert workers, 'isolated worker missing'
                    for pid in workers:
                        os.kill(pid,signal.SIGSTOP)
                alice = future.result(timeout=6)
            assert alice.returncode != 0 and len(alice.stdout) < 2, (alice.returncode, alice.stdout)
            assert site.cutoff.wait(1), 'upstream leg survived cutoff'
            assert time.monotonic() - begin < 4, 'cutoff exceeded lease and test scheduling budget'
            assert request('alice').returncode != 0, 'Lapsed worker reused old grant'
            if egress:
                # The slow request went through a tunnel too, as did each since.
                taken = egress.take()
                assert taken and set(taken) == set(through_egress), taken
            if shared:
                assert request('bob').returncode == 0, 'Alice cutoff affected Bob'
                assert request('alice-other-context').returncode == 0, 'Cutoff crossed Contexts using the same identity'
                # Bob's 30s authority remains valid on both legs. A retirement
                # notification accelerates cutoff without waiting for renewal.
                site.cutoff = threading.Event()
                site.slow_started = threading.Event()
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                    future = pool.submit(request,'bob',(),'/slow')
                    assert site.slow_started.wait(4)
                    broker.retired['bob'].set()
                    assert future.result(timeout=4).returncode != 0
                    assert site.cutoff.wait(1)
                if egress:
                    # The certificate revalidation below does not depend on the route.
                    return
                # Revalidation at 10s imports a new, shorter evidence deadline.
                # The idle transport must close at that deadline ahead of the
                # next periodic check and its still-current 30-second leases.
                site.cutoff = threading.Event()
                site.slow_started = threading.Event()
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                    future = pool.submit(request,'alice-other-context',(),'/slow',24)
                    assert site.slow_started.wait(4)
                    deadline = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0) + datetime.timedelta(seconds=14)
                    publish_crl(crl, ca, 2, deadline)
                    assert site.cutoff.wait(deadline.timestamp() - time.time() + 2), 'Idle upstream survived shortened CRL validity'
                    assert time.time() >= deadline.timestamp() - 1, 'Idle upstream closed before shortened validity'
                    result = future.result(timeout=1)
                    assert result.returncode not in (0, 28), (result.returncode, result.stderr)
        finally:
            child.terminate()
            child.wait(timeout=6)


def main():
    binary=str(Path(sys.argv[1]).resolve())
    options = sys.argv[2:]
    silent = '--silent-egress-proxy' in options
    if silent:
        options.remove('--silent-egress-proxy')
    assert len(options) % 2 == 0 and set(options[::2]) <= {'--worker-sandbox', '--startup-fails', '--landlock'}, __doc__
    options = dict(zip(options[::2], options[1::2]))
    sandbox = options.get('--worker-sandbox')
    assert sandbox in (None, 'namespaces', 'filter'), __doc__
    startup_fails = options.get('--startup-fails')
    landlock = options.get('--landlock')
    assert landlock in (None, 'unavailable'), __doc__
    assert not (silent and startup_fails), __doc__
    with tempfile.TemporaryDirectory(prefix='countersign-gateway-test-') as td:
        os.umask(0o077)
        dir=Path(td)
        ca=identity(dir,'ca')
        # A CA that signs nothing the site presents.
        identity(dir,'other-ca')
        upstream = ['site.test','direct.test','a.wild.test','untrusted.test']
        for name,hosts in [('broker',['localhost']),('listener',['localhost']),('upstream',upstream)]:
            identity(dir,name,ca,hosts)
        identities={u: identity(dir,u,ca) for u in ('alice','bob')}
        identities['alice-other-context'] = identities['alice']
        def tls(name):
            ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(dir/f'{name}.pem',dir/f'{name}.key')
            return ctx
        site_tls=tls('upstream')
        site_tls.verify_mode=ssl.CERT_REQUIRED
        site_tls.load_verify_locations(dir/'ca.pem')
        # Ask the kernel for its default interface, without sending any datagram.
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
            s.connect(('192.0.2.1',9))
            ip=s.getsockname()[0]
        with socket.socket() as s:
            s.bind(('127.0.0.1',0))
            # Nothing listens here once the socket closes.
            nothing = s.getsockname()
        with (server(ip,Site,site_tls) as site, server('127.0.0.1',Broker,tls('broker')) as broker,
              egress_proxy({'site.test': ip, 'wrong.test': ip, 'untrusted.test': ip, 'a.wild.test': ip,
                            'unlisted.test': ip, 'ungranted.test': ip, 'closed.test': b'', 'unreachable.test': nothing,
                            'silent.test': KeptOpen(b''),
                            'garbled.test': b'SSH-2.0-test egress proxy\r\n\r\n',
                            'banner.test': KeptOpen(b'SSH-2.0-test egress proxy\r\n'), 'stub.test': KeptOpen(b'SSH-2.0'),
                            'lf.test': KeptOpen(b'HTTP/1.1 403 Forbidden\n\n')}) as egress):
            if silent:
                do_test(dir,binary,ip,site,broker,identities,ca,False,sandbox=sandbox,egress=egress,silent=True)
                print('sidecar Gateway with a silent egress proxy failed closed')
                return
            for shared in (False,True):
                do_test(dir,binary,ip,site,broker,identities,ca,shared,sandbox=sandbox,startup_fails=startup_fails,
                        landlock=landlock,ignored=egress)
                print(('shared' if shared else 'sidecar')+(' Gateway refused to start' if startup_fails
                                                           else ' Gateway mTLS passed'))
            if startup_fails:
                return
            for shared in (False,True):
                do_test(dir,binary,ip,site,broker,identities,ca,shared,sandbox=sandbox,egress=egress)
                print(('shared' if shared else 'sidecar')+' Gateway mTLS through the egress proxy passed')
                # Nothing listens at the egress proxy's address.
                do_test(dir,binary,ip,site,broker,identities,ca,shared,sandbox=sandbox,egress=egress,
                        unusable={'egress_proxy': f'http://localhost:{nothing[1]}'})
                # The egress proxy's only address is inside `denied_networks`.
                do_test(dir,binary,ip,site,broker,identities,ca,shared,sandbox=sandbox,egress=egress,
                        unusable={'denied_networks': ['127.0.0.0/8', '::1/128']})
                print(('shared' if shared else 'sidecar')+' Gateway without a usable egress proxy failed closed')
            do_test(dir,binary,ip,site,broker,identities,ca,True,filter_kill=True,sandbox=sandbox)
            print('filter-killed grant worker fenced')


if __name__ == '__main__':
    main()
