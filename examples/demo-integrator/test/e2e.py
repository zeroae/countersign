"""Run inside an isolated dbus-run-session + Xvfb. Uses real installed token keys, the
packaged desktop renderer, two server processes and an unprivileged curl Workload."""
import argparse
import contextlib
import http.cookiejar
import json
import os
from pathlib import Path
import secrets
import shlex
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.request
from playwright.sync_api import sync_playwright, expect

EXAMPLE=Path(__file__).resolve().parents[1]
ROOT=EXAMPLE.parents[1]
sys.path.insert(0,str(EXAMPLE))
from prepare import prepare


def port():
    with socket.socket() as s:
        s.bind(('127.0.0.1',0))
        return s.getsockname()[1]


def run(directory, app, count):
    directory.chmod(0o755)
    private=directory/'private';private.mkdir(mode=0o700)
    public=directory/'trust';public.mkdir(mode=0o755)
    private_env=dict(XDG_DATA_HOME=str(private/'data'),XDG_CONFIG_HOME=str(private/'config'),
                     XDG_RUNTIME_DIR=str(private/'runtime'))
    (private/'runtime').mkdir(mode=0o700)
    os.environ.update(private_env)
    os.environ.pop('GNOME_KEYRING_CONTROL',None)
    subprocess.run(['gnome-keyring-daemon','--unlock','--components=secrets'],
                   input=secrets.token_hex(32).encode(),check=True,stdout=subprocess.DEVNULL)
    fixture=prepare(private/'demo', count=count)
    token_file=private/'workload.jwt'
    ca=fixture/'ca.pem'
    admin=fixture/'admin.token'
    broker_port,proxy_port,ui_port,cdp_port=(port() for _ in range(4))
    origin=f'https://localhost:{ui_port}'
    broker_url=f'https://localhost:{broker_port}'
    proxy_url=f'http://127.0.0.1:{proxy_port}'
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
        s.connect(('192.0.2.1',9))
        local_ip=s.getsockname()[0]
    hosts=private/'hosts'
    hosts.write_text(Path('/etc/hosts').read_text()+'\n'+local_ip+' site.test\n')
    dest=dict(id='demo-site',version=1,pattern='site.test:9444')
    binding=dict(integrator='demo',user='demo-user',context='demo-context',workload='demo-curl',workload_generation=1)
    broker_config=dict(origin=f'localhost:{ui_port}',listen=f'127.0.0.1:{broker_port}',integrator='demo',
        database=str(private/'broker.db'),backend_token_file=str(fixture/'backend.token'),
        workload_hmac_key_file=str(fixture/'workload.hmac'),client_ca_file=str(fixture/'client-ca.pem'),
        tls=dict(certificate_path=str(fixture/'broker.pem'),key_path=str(fixture/'broker.key')),destinations=[dest])
    gateway_config=dict(listen=f'127.0.0.1:{proxy_port}',proxy_url=proxy_url,ca_output=str(public/'sidecar.pem'),
        broker_url=broker_url,broker_ca=str(ca),workload_token=str(token_file),workload=binding,
        destinations=[dict(**dest,private_networks=[local_ip+'/32'],roots=str(ca))])
    for label,conf in [('broker',broker_config),('gateway',gateway_config)]:
        (private/(label+'.json')).write_text(json.dumps(conf))
    tools=private/'bin';tools.mkdir()
    opener=tools/'xdg-open'
    opener.write_text('#!/bin/sh\nprintf "%s\\n" "$1" > "$DEMO_PAIRING_URL"\n')
    opener.chmod(0o700)
    env=dict(os.environ,NODE_EXTRA_CA_CERTS=str(ca),COUNTERSIGN_PKCS11_MODULE=str(next(Path('/usr/lib').glob('*/softhsm/libsofthsm2.so'))),
             DEMO_SECRETS=str(fixture),PORT=str(ui_port),BROKER_URL=broker_url,INTEGRATOR_ORIGIN=origin,
             DEMO_PAIRING_URL=str(private/'url'),WORKLOAD_TOKEN_FILE=str(token_file),PATH=str(tools)+':'+os.environ['PATH'])
    binary=Path(os.environ.get('CARGO_TARGET_DIR',str(ROOT/'target')))/'debug'
    ctx=ssl.create_default_context(cafile=str(ca))
    web=urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx),
        urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    csrf=''
    def api(path,data=None):
        req=urllib.request.Request(origin+'/api/'+path,data=None if data is None else json.dumps(data).encode(),
            headers={'Origin':origin,'Content-Type':'application/json','X-CSRF-Token':csrf})
        return json.loads(web.open(req,timeout=10).read())
    with contextlib.ExitStack() as cleanup:
        def start(label,command,extra_env=None):
            log=cleanup.enter_context(open(private/(label+'.log'),'wb'))
            child=subprocess.Popen(command,env=dict(env,**(extra_env or {})),stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
            def stop():
                if child.poll() is None:
                    os.killpg(child.pid,signal.SIGTERM)
                    try:child.wait(timeout=4)
                    except subprocess.TimeoutExpired:
                        os.killpg(child.pid,signal.SIGKILL);child.wait(4)
            cleanup.callback(stop)
            return child
        start('broker',[binary/'countersign-broker',private/'broker.json'])
        start('site',['node',EXAMPLE/'upstream.js'])
        start('integrator',['node',EXAMPLE/'integrator.js'])
        # The isolated hosts file maps just the local fixture service. The Gateway
        # still resolves, checks the approved address class and pins its socket.
        gateway=start('gateway',[binary/'countersign-gateway','serve',private/'gateway.json'], {
            'LD_PRELOAD':str(next(Path('/usr/lib').glob('*/libnss_wrapper.so'))),
            'NSS_WRAPPER_HOSTS':str(hosts)})
        subprocess.run(['timeout','30','bash','-c',
            'inotifywait -qq -t 25 -e moved_to "$1" || test -f "$1/workload.jwt"',
            'wait-for-demo',private],check=False,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL) if not token_file.exists() and shutil.which('inotifywait') else None
        # Drive enrollment over the real main process/preload isolation boundary.
        # Ubuntu restricts unprivileged user namespaces by AppArmor profile.
        # Give only this test executable its Chromium namespace sandbox during
        # this run. Leave system-wide settings and the setuid helper untouched.
        restriction=Path('/proc/sys/kernel/apparmor_restrict_unprivileged_userns')
        if restriction.exists() and restriction.read_text().strip()=='1':
            if any(c in str(app) for c in ['"', '\\', '*', '?', '[', ']', '{', '}', '\n']):
                raise ValueError('Unexpected AppArmor attachment path')
            profile=private/'desktop.apparmor'
            profile.write_text('abi <abi/4.0>,\ninclude <tunables/global>\nprofile countersign-e2e-'+
                secrets.token_hex(8)+' "'+str(app)+'" flags=(unconfined) { userns, }\n')
            subprocess.run(['sudo','-n','apparmor_parser','-a',profile],check=True)
            cleanup.callback(subprocess.run,['sudo','-n','apparmor_parser','-R',str(profile)],check=True)
        start('desktop',[app,'--user-data-dir='+str(private/'desktop'),'--remote-debugging-port='+str(cdp_port),
                         '--password-store=gnome-libsecret'])
        with sync_playwright() as pw:
            end=time.monotonic()+40
            browser=None
            for _ in range(80):
                try:
                    browser=pw.chromium.connect_over_cdp('http://127.0.0.1:'+str(cdp_port),timeout=2500)
                    break
                except Exception:
                    if time.monotonic()>end:raise
                    time.sleep(.25)
            assert browser
            context=browser.contexts[0]
            page=context.pages[0] if context.pages else context.wait_for_event('page',timeout=15000)
            page.set_default_timeout(25000)
            page.get_by_label('Integrator origin').fill(origin)
            page.get_by_role('button',name='Pair',exact=True).click()
            expect(page.locator('#pending')).to_contain_text('Pairing code',timeout=30000)
            code=page.locator('#pending').inner_text().split('Pairing code ')[-1].strip()
            from urllib.parse import urlsplit,parse_qs
            attempt=parse_qs(urlsplit((private/'url').read_text().strip()).query)['attempt'][0]
            api('login',{'password':(fixture/'login.secret').read_text().strip()})
            csrf=api('session')['csrf']
            api('pair',{'attempt':attempt,'code':code})
            page.get_by_role('button',name='Confirm pairing').click()
            expect(page.locator('#pairs')).to_contain_text('Connected')
            assert token_file.is_file() and (public/'sidecar.pem').is_file(), 'runtime has no credentials or CA'
            # Confirm the real Workload UID can read the public CA and cannot
            # inspect the Gateway process's memory, private mount or credential.
            uid=['sudo','-n','-u','nobody','--']
            subprocess.run(uid+['test','-r',str(public/'sidecar.pem')],check=True)
            for path in [private,token_file,Path('/proc')/str(gateway.pid)/'mem']:
                assert subprocess.run(uid+['test','-r',str(path)]).returncode!=0
            args=uid+['env','NO_PROXY=','no_proxy=','HTTPS_PROXY='+proxy_url,'SSL_CERT_FILE='+str(public/'sidecar.pem'),
                     'curl','--silent','--show-error','--fail','--max-time','95','https://site.test:9444/']
            with subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE) as curl:
                try:
                    rows=page.locator('#requests .identity')
                    expect(rows).to_have_count(count,timeout=30000)
                    approve=page.get_by_role('button',name='Approve',exact=True)
                    expect(approve).to_be_disabled()
                    selected=rows.last
                    fingerprint=selected.locator('small').inner_text().removeprefix('SHA-256 ')
                    selected.get_by_role('radio').check()
                    approve.click()
                    output,errors=curl.communicate(timeout=60)
                    assert curl.returncode==0,errors.decode()
                    assert json.loads(output)['fingerprint']==fingerprint
                    assert fingerprint in json.loads((fixture/'fingerprints.json').read_text())
                finally:
                    if curl.poll() is None:curl.terminate();curl.wait(5)
            print(f'PASS: selected one of {count} native identities; isolated curl and upstream confirmed {fingerprint}',flush=True)


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--app',type=Path,required=True)
    parser.add_argument('--count',type=int,choices=[2,3],default=3)
    args=parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='countersign-e2e-') as temp:
        try:run(Path(temp),args.app.resolve(),args.count)
        except BaseException:
            for log in (Path(temp)/'private').glob('*.log'):
                # Service logs contain no grant credentials or HTTP bodies.
                print(log.name,log.read_text(errors='replace')[-2500:],file=sys.stderr)
            raise
