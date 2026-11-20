"""Exercise real Linux Gateway processes against a test-only grant authority and mTLS site.

Usage: python3 crates/countersign-gateway/tests/runtime.py target/debug/countersign-gateway
Requires bubblewrap, libnss-wrapper, curl with HTTPS proxy support, and python-cryptography.
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


class Fixture(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        # Cancelling an outstanding poll or forcibly cutting off either TLS leg
        # can reset the fixture socket while the HTTP library is reading it.
        if not isinstance(sys.exc_info()[1], (BrokenPipeError, ConnectionResetError, ssl.SSLEOFError)):
            super().handle_error(request, client_address)


class Site(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        fingerprint = hashlib.sha256(self.connection.getpeercert(binary_form=True)).hexdigest().encode()
        if self.path == '/slow':
            self.send_response(200)
            self.send_header('content-length', '1000000')
            self.end_headers()
            self.wfile.write(b'x')
            self.server.slow_started.set()
            self.connection.settimeout(25)
            try:
                if not self.connection.recv(1):
                    self.server.cutoff.set()
            except (ConnectionResetError, ssl.SSLEOFError):
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
        user, key, grant = authority.accounts[token]
        if authority.shared and self.headers.get('X-Countersign-Gateway') != authority.service_secret:
            self.send_error(403)
            return
        frame = json.loads(self.rfile.read(int(self.headers['content-length'])))
        body = frame['body']
        now = int(time.time() * 1000)
        msg = frame['type']
        if msg in ('connect', 'lookup') and body['workload'] == grant['workload'] and body['host'] == authority.host:
            kind = 'activate'
            value = {'activation': {'grant': grant, 'offer': user, 'approval': user,
                                     'expires_at_ms': authority.expires_at},
                     'chain': [authority.public[user]]}
        elif msg == 'watch' and body == grant:
            retired = authority.retired[user].wait(5)
            kind, value = ('retire' if retired else 'no_change'), grant
        elif msg == 'observed' and body['grant'] == grant and body['host'] == authority.host:
            kind = 'observed'
            value = body
            with authority.observation_change:
                received = authority.observations.setdefault((user,body['tls_connection']),set())
                received.add(body['observation'])
                authority.observation_change.notify_all()
        elif msg == 'renew_lease' and body['grant'] == grant:
            kind = 'lease'
            budget = 2000 if user == 'alice' else 30000
            value = {'binding': body, 'disposition': {'granted': {'budget_ms': budget, 'valid_until_ms': now + budget}}}
        elif msg == 'sign' and body['binding']['grant'] == grant and body['binding']['host'] == authority.host:
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
    httpd = Fixture((addr, 0), handler)
    httpd.socket = tls.wrap_socket(httpd.socket, server_side=True)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield httpd
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join()


def do_test(dir, binary, ip,site, broker, identities, ca, shared, filter_kill=False):
    host = f'site.test:{site.server_port}'
    broker.host = host
    broker.accounts = {}
    broker.retired = {user: threading.Event() for user in identities}
    broker.public = {}
    broker.observations = {}
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
        grant = {'workload':workload,'grant':user,'grant_version':1,'worker':user,'worker_generation':1,
                 'scope':{'entry_id':'site','entry_version':1,'pattern':host},
                 'device':{'pairing':user,'key':user,'channel_generation':1}, 'cert_sha256':b64(hashlib.sha256(der).digest())}
        bindings[user] = workload
        broker.public[user] = b64(der)
        broker.accounts[token(workload)] = (user,key,grant)
    with socket.socket() as tmp:
        tmp.bind(('127.0.0.1',0))
        port = tmp.getsockname()[1]
    pub = dir / ('ca.pem' if shared else 'public.pem')
    proxy = ('https' if shared else 'http') + f'://localhost:{port}'
    config = {'listen':f'127.0.0.1:{port}', 'proxy_url':proxy,'ca_output':str(pub),
              'broker_url':f'https://localhost:{broker.server_port}', 'broker_ca':str(dir/'ca.pem'),
              'clock_uncertainty_ms':100,
              'destinations':[{'id':'site','version':1,'pattern':host,'roots':str(dir/'ca.pem'),'private_networks':[ip+'/32']}]}
    if shared:
        crl = dir / 'site.crl'
        publish_crl(crl, ca, 1, datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5))
        config['destinations'][0]['revocation'] = {'kind':'crl', 'files':[str(crl)]}
        config['shared']={'listener_cert':str(dir/'listener.pem'),'listener_key':str(dir/'listener.key'),
                          'gateway_token':str(dir/'service'),
                          'ca':{'type':'local','cert':str(dir/'ca.pem'),'key':str(dir/'ca.key')}}
    else:
        (dir/'sidecar.token').write_text(token(bindings['alice']))
        config.update(workload=bindings['alice'],workload_token=str(dir/'sidecar.token'))
    (dir/'config.json').write_text(json.dumps(config))
    hosts = dir/'hosts'
    hosts.write_text('127.0.0.1 localhost\n'+ip+' site.test\n')
    # Override /etc/hosts only for the Gateway parent. Grant workers are then
    # isolated by the production launcher and receive only preconnected streams.
    library = os.environ.get('NSS_WRAPPER_LIBRARY') or str(next(Path('/usr/lib').glob('*/libnss_wrapper.so')))
    with subprocess.Popen([binary,'serve',str(dir/'config.json')], stderr=subprocess.PIPE, text=True,
                          env={**os.environ,'LD_PRELOAD':library,'NSS_WRAPPER_HOSTS':str(hosts)}) as child:
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
            assert wait_for_log(r'Gateway worker sandbox "namespaces": namespaces, non-dumpable, '
                                r'Landlock (ABI v[1-9]\d*|unavailable), seccomp allow-list'), log
            def request(user,extra=(),path='/', timeout=8):
                args=['curl','--silent','--show-error','--fail','--max-time',str(timeout),'--noproxy','','--proxy',proxy,
                      '--proxy-cacert',str(dir/'ca.pem'),'--cacert',str(pub)]
                if shared:
                    args+=['--proxy-header','Proxy-Authorization: Bearer '+token(bindings[user])]
                return subprocess.run(args + list(extra) + ['https://'+host+path], capture_output=True, timeout=timeout+2)
            users = list(identities) if shared else ['alice']
            if filter_kill:
                # Only Alice's grant worker runs. A grant worker the allow-list
                # kills dies of SIGSYS, so deliver that signal to it: the
                # supervisor cannot tell the two apart.
                assert request('alice').returncode == 0
                leaves = [pid for pid in descendants(child.pid) if not descendants(pid)]
                assert len(leaves) == 1, leaves
                os.kill(leaves[0], signal.SIGSYS)
                assert wait_for_log(r"Gateway grant worker killed by the worker sandbox's filter \(SIGSYS\); "
                                    r'grant fenced'), log
                assert request('alice').returncode != 0, 'A grant whose worker the filter killed was served again'
                assert request('bob').returncode == 0, "Alice's killed grant worker affected Bob"
                return
            with concurrent.futures.ThreadPoolExecutor(max_workers=len(users)) as pool:
                results = list(pool.map(request,users))
            for user,res in zip(users,results):
                assert res.returncode==0,(user,res.stderr)
                expected=identities[user][1].fingerprint(hashes.SHA256()).hex().encode()
                assert res.stdout==expected,(user,res.stdout)
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
    with tempfile.TemporaryDirectory(prefix='countersign-gateway-test-') as td:
        os.umask(0o077)
        dir=Path(td)
        ca=identity(dir,'ca')
        for name,hosts in [('broker',['localhost']),('listener',['localhost']),('upstream',['site.test'])]:
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
        with server(ip,Site,site_tls) as site, server('127.0.0.1',Broker,tls('broker')) as broker:
            for shared in (False,True):
                do_test(dir,binary,ip,site,broker,identities,ca,shared)
                print(('shared' if shared else 'sidecar')+' Gateway mTLS passed')
            do_test(dir,binary,ip,site,broker,identities,ca,True,filter_kill=True)
            print('filter-killed grant worker fenced')


if __name__ == '__main__':
    main()
