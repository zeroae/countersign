"""Linux desktop demonstration. Run --help for prerequisites and usage."""
import argparse
import base64
import contextlib
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import secrets
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import threading

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
DESTINATION = {"id": "demo-site", "version": 1, "pattern": "site.test:9444"}


def run(*args, seconds=60, **options):
    return subprocess.run([str(a) for a in args], check=True, timeout=seconds, **options)


def prepare_config(state, fixture, port):
    for name in ("broker","database","gateway","integrator","credential","site","public"):
        (state/name).mkdir(mode=0o700)
    # Only this directory is visible to the workload. The outer host directory
    # remains private. Read permissions on the actual CA are independently tested.
    (state/"public").chmod(0o755)
    for service, names in {
        "broker": ["client-ca.pem","backend.token","workload.hmac","broker.pem","broker.key"],
        "gateway": ["ca.pem"],
        "site": ["site.pem","site.key","client-ca.pem"],
        "integrator": ["ca.pem","integrator.pem","integrator.key","backend.token","login.secret"],
    }.items():
        for name in names:
            shutil.copyfile(fixture/name, state/service/name)
    config = dict(origin=f"localhost:{port}",listen="0.0.0.0:9443",integrator="demo",database="/state/broker.db",
                  backend_token_file="/config/backend.token",workload_hmac_key_file="/config/workload.hmac",
                  client_ca_file="/config/client-ca.pem",tls=dict(certificate_path="/config/broker.pem",
                  key_path="/config/broker.key"),destinations=[DESTINATION])
    (state/"broker/broker.json").write_text(json.dumps(config))


def gateway_config(state, address):
    network = str(ipaddress.IPv4Network(address+"/32"))
    config = dict(listen="@WORKLOAD_IP@:8080",proxy_url="http://gateway:8080",ca_output="/trust/sidecar.pem",
                  broker_url="https://broker:9443",broker_ca="/config/ca.pem",workload_token="/credential/workload.jwt",
                  workload=dict(integrator="demo",user="demo-user",context="demo-context",
                                workload="demo-curl",workload_generation=1),
                  destinations=[dict(**DESTINATION, private_networks=[network], roots="/config/ca.pem")])
    (state/"gateway/gateway.json").write_text(json.dumps(config))


def use_namespaces(stack, state, name):
    override=os.environ.get("CS_DEMO_GATEWAY_PROFILE")
    restriction=Path("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
    if override or not restriction.exists() or restriction.read_text().strip()!="1":
        return override or "unconfined", []
    # Restrict the temporary exception to the named processes in this demo.
    # Preserve the host-wide sandbox/userns settings.
    profile=state/"demo.apparmor"
    profile.write_text(f"abi <abi/4.0>,\ninclude <tunables/global>\nprofile {name} flags=(unconfined) {{ userns, }}\n")
    run("sudo","apparmor_parser","-a",profile)
    stack.callback(run,"sudo","apparmor_parser","-R",profile)
    return name, ["aa-exec","-p",name,"--"]


def terminate(child):
    if child.poll() is None:
        os.killpg(child.pid,signal.SIGTERM)
        try:
            child.wait(timeout=6)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid,signal.SIGKILL)
            child.wait(timeout=5)


def browser_command(args):
    if args.browser:
        return args.browser.resolve()
    for name in ("chromium","google-chrome","chromium-browser"):
        if binary:=shutil.which(name):
            return Path(binary)
    from playwright.sync_api import sync_playwright
    with sync_playwright() as pw:
        path=Path(pw.chromium.executable_path)
    if not path.is_file():
        raise RuntimeError("Install Chromium or run 'python -m playwright install chromium' in the demo venv.")
    return path


def devtools(child):
    # Consume the readiness message from this child's live stderr. Avoid fixed
    # sleeps, global process searches and guessing a listening debug port.
    ready=threading.Event()
    endpoints=[]
    def listen():
        for line in child.stderr:
            if line.startswith("DevTools listening on ws://127.0.0.1:"):
                endpoints.append(line.strip().split()[-1])
                ready.set()
        ready.set()
    threading.Thread(target=listen,daemon=True).start()
    if not ready.wait(30) or not endpoints:
        raise RuntimeError("Desktop failed to start with its Chromium sandbox. Check DISPLAY and user namespace permissions.")
    return endpoints[0]


def record_job(state, url, completed):
    """Save the Workload's last result for the Integrator's /job page."""
    result={"url":url,"ok":completed.returncode==0}
    if result["ok"]:
        try:
            body=json.loads(completed.stdout)
            result.update(http_status=200,fingerprint=str(body["fingerprint"]),subject=str(body["subject"]))
        except (ValueError,KeyError,TypeError):
            result.update(ok=False,error="The site returned an unexpected response.")
    else:
        lines=completed.stderr.strip().splitlines()
        result["error"]=lines[-1] if lines else f"curl exited with status {completed.returncode}."
    target=state/"integrator"/"job.json"
    staged=target.with_suffix(".next")
    staged.write_text(json.dumps(result))
    staged.replace(target)


def verify(desktop, browser, origin, fixture, curl, state, url):
    from playwright.sync_api import sync_playwright, expect
    with sync_playwright() as pw:
        session=pw.chromium.connect_over_cdp(desktop)
        desktop_page=session.contexts[0].pages[0]
        web=pw.chromium.connect_over_cdp(browser).contexts[0]
        desktop_page.get_by_label("Integrator origin").fill(origin)
        with web.expect_event("page", timeout=35000) as opened:
            desktop_page.get_by_role("button",name="Pair",exact=True).click()
        tab=opened.value
        # The Companion shows the code grouped for reading, e.g. "7B9D F613 D8".
        expect(desktop_page.locator("#pairing .code")).to_be_visible()
        code=desktop_page.locator("#pairing .code").inner_text().replace(" ","")
        tab.get_by_label("Demo login secret").fill((fixture/"login.secret").read_text().strip())
        tab.get_by_role("button",name="Sign in").click()
        tab.get_by_label("Code from your Companion").fill(code)
        tab.get_by_role("button",name="Confirm pairing").click()
        expect(tab.locator("#message")).to_contain_text("Confirm the account")
        desktop_page.get_by_role("button",name="Confirm pairing").click()
        expect(desktop_page.locator("#pairs")).to_contain_text("Connected")
        with subprocess.Popen(curl, stdout=subprocess.PIPE,text=True) as workload:
            try:
                choices=desktop_page.locator("#requests .identity")
                expect(choices).to_have_count(3,timeout=45000)
                approve=desktop_page.get_by_role("button",name="Approve",exact=True)
                expect(approve).to_be_disabled()
                fingerprint="".join(choices.last.locator(".fp-g").all_inner_texts())
                if len(fingerprint)!=64:
                    raise RuntimeError("The Companion did not show a full SHA-256 fingerprint")
                choices.last.get_by_role("radio").check()
                approve.click()
                output,_=workload.communicate(timeout=60)
                if workload.returncode or json.loads(output)["fingerprint"]!=fingerprint:
                    raise RuntimeError("Upstream did not accept the selected native certificate")
                print("Compose mTLS accepted selected SHA-256 "+fingerprint,flush=True)
                # The Integrator's job page reads the result the launcher records.
                record_job(state,url,subprocess.CompletedProcess(curl,workload.returncode,output,""))
                job=web.new_page()
                job.goto(origin+"/job")
                expect(job.locator("#job-fingerprint")).to_have_text(fingerprint)
                job.get_by_label("SHA-256 you selected in the Companion").fill(fingerprint)
                job.get_by_role("button",name="Compare").click()
                expect(job.locator("#match")).to_be_visible()
                print("Job page shows the fingerprint the site received",flush=True)
            finally:
                if workload.poll() is None:
                    workload.terminate()
                    workload.wait(timeout=5)


def session(args):
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from prepare import prepare, start_demo_keyring
    if os.getuid() in (0,65534):
        raise RuntimeError("Launch this desktop demo as a regular user distinct from workload UID 65534.")
    app=args.app.resolve()
    browser=browser_command(args)
    for executable in (app,browser):
        if not os.access(executable, os.X_OK):
            raise RuntimeError(f"Missing executable: {executable}")
    with tempfile.TemporaryDirectory(prefix="countersign-demo-") as tmp, contextlib.ExitStack() as stack:
        state=Path(tmp)
        os.umask(0o077)
        # All provider and desktop state belongs to this one private D-Bus session.
        start_demo_keyring(state)
        fixture=prepare(state/"provider")
        project="countersign-demo-"+secrets.token_hex(5)
        profile,prefix=use_namespaces(stack,state,project)
        os.environ.update(CS_DEMO_STATE=str(state),CS_DEMO_UID=str(os.getuid()),CS_DEMO_GID=str(os.getgid()),
                          CS_DEMO_PORT=str(args.port),CS_DEMO_GATEWAY_PROFILE=profile)
        prepare_config(state,fixture,args.port)
        compose=["docker","compose","-p",project,"-f",str(HERE/"compose.yaml")]
        run(*compose,"config","-q")
        run(*compose,"build","broker","gateway","site",seconds=580)
        stack.callback(run,*compose,"down","--volumes","--remove-orphans",seconds=60)
        run(*compose,"up","--wait","--wait-timeout","55","broker","site","integrator",seconds=100)
        site=run(*compose,"ps","-q","site",capture_output=True,text=True).stdout.strip()
        address=run("docker","inspect","-f","{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
                    site,capture_output=True,text=True).stdout.strip()
        gateway_config(state,address)
        run(*compose,"up","--wait","--wait-timeout","35","gateway")
        # The Workload can read the newly generated public trust anchor and has
        # no credential/control-plane mount or Gateway process in its namespace.
        gateway_id=run(*compose,"ps","-q","gateway",capture_output=True,text=True).stdout.strip()
        gateway_pid=run("docker","inspect","-f","{{.State.Pid}}",gateway_id,capture_output=True,text=True).stdout.strip()
        if not gateway_pid.isdecimal() or int(gateway_pid)<=1: raise RuntimeError("invalid Gateway host PID")
        run(*compose,"exec","-T","site","node","-e",
            "const s=require('node:net').connect(8080,'gateway');s.on('connect',()=>process.exit(1));"
            "s.setTimeout(3000,()=>process.exit(2));s.on('error',e=>process.exit(e.code==='ECONNREFUSED'?0:3));")
        run(*compose,"run","--rm","-T","--entrypoint","sh","workload","-ec",
            'test "$(id -u)" = 65534 && test -r /trust/sidecar.pem && test ! -e /credential && test ! -e /config && '
            'test ! -r "/proc/$1/mem" && test ! -r "/proc/$1/fd" && '
            'test "$(ls -A /trust)" = sidecar.pem && ! grep -q "PRIVATE KEY" /trust/sidecar.pem',
            "check-workload",gateway_pid)
        origin=f"https://localhost:{args.port}"
        cert=x509.load_pem_x509_certificate((fixture/"integrator.pem").read_bytes())
        spki=cert.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
        pin=base64.b64encode(hashlib.sha256(spki).digest()).decode()
        browser_args=[*prefix,str(browser),"--user-data-dir="+str(state/"browser"),"--no-first-run",
                      "--no-default-browser-check","--ignore-certificate-errors-spki-list="+pin]
        tools=state/"bin"
        tools.mkdir()
        opener=tools/"xdg-open"
        opener.write_text("#!/bin/sh\ncase \"$1\" in "+origin+"/countersign/*) exec "+
                          shlex.join(browser_args)+" \"$1\" ;; *) exit 1 ;; esac\n")
        opener.chmod(0o700)
        os.environ.update(NODE_EXTRA_CA_CERTS=str(fixture/"ca.pem"),
                          COUNTERSIGN_PKCS11_MODULE=str(next(Path("/usr/lib").glob("*/softhsm/libsofthsm2.so"))),
                          PATH=str(tools)+":"+os.environ["PATH"])
        debug=["--remote-debugging-port=0"] if args.verify else []
        def start(command):
            child=subprocess.Popen(command,start_new_session=True,stderr=subprocess.PIPE if args.verify else None,text=True)
            stack.callback(terminate,child)
            return devtools(child) if args.verify else None
        browser_endpoint=start(browser_args+debug+[origin])
        desktop_endpoint=start([*prefix,str(app),"--user-data-dir="+str(state/"desktop"),"--password-store=gnome-libsecret",*debug])
        url="https://site.test:9444/"
        curl=[*compose,"run","--rm","-T","workload","--fail","--silent","--show-error","--max-time","95",url]
        if args.verify:
            verify(desktop_endpoint,browser_endpoint,origin,fixture,curl,state,url)
            return
        print(f"In the Companion's Integrators tab, enter {origin} and choose Pair. Sign in to the demo tab using the secret from {fixture/'login.secret'}.")
        print("Enter the Companion pairing code in the browser and confirm the pairing in the Companion.")
        print("Type curl below to request https://site.test:9444/. Choose a certificate and approve in the Companion.")
        print(f"The Integrator's {origin}/job page shows the fingerprint the site received.")
        print("Type quit to remove this demo's containers, keys, trust anchor and profiles.")
        for line in sys.stdin:
            if line.strip()=="quit": return
            if line.strip()=="curl":
                completed=subprocess.run(curl,timeout=110,capture_output=True,text=True)
                sys.stdout.write(completed.stdout+"\n")
                sys.stderr.write(completed.stderr)
                record_job(state,url,completed)
                print(f"Result saved. Open {origin}/job to compare the fingerprint with your approval.",flush=True)
            else: print("Enter curl or quit.")


def main():
    parser=argparse.ArgumentParser(description=__doc__,epilog="Requires Docker Compose, D-Bus, GNOME Keyring, "
        "SoftHSM2, libsecret tools, a sandbox-capable Linux GUI session, Chromium and a packaged Companion. "
        "Install the Python dependencies from test/fixture-requirements.txt.")
    parser.add_argument("--app",type=Path,required=True,help="installed or unpacked Linux Companion executable")
    parser.add_argument("--browser",type=Path,help="Chromium executable (defaults to system or Playwright Chromium)")
    parser.add_argument("--port",type=int,default=8443,help="loopback HTTPS port (default 8443)")
    parser.add_argument("--verify",action="store_true",help="drive the demo's actual browser and Companion UIs")
    parser.add_argument("--session",action="store_true",help=argparse.SUPPRESS)
    args=parser.parse_args()
    if not 1024<=args.port<=65535: parser.error("choose an unprivileged port from 1024 to 65535")
    if not args.session:
        os.execvp("dbus-run-session",["dbus-run-session","--",sys.executable,str(Path(__file__).resolve()),"--session",*sys.argv[1:]])
    session(args)


if __name__=="__main__":
    try: main()
    except KeyboardInterrupt: pass
