"""Qualify the OS/architecture of this runner using the actual prebuilt addon."""
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]

def run(*args, **options):
    return subprocess.run(args, check=True, timeout=180, **options)

def cert(authority, issuer, label, key, ca):
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (x509.CertificateBuilder().issuer_name(issuer)
               .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, label)]))
               .public_key(key).serial_number(x509.random_serial_number())
               .not_valid_before(now-datetime.timedelta(minutes=5))
               .not_valid_after(now+datetime.timedelta(hours=2))
               .add_extension(x509.BasicConstraints(ca=ca,path_length=None), True)
               .add_extension(x509.KeyUsage(not ca,False,False,False,False,ca,ca,False,False),True))
    if not ca:
        builder=builder.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),False)
    return builder.sign(authority, hashes.SHA256())

def provision(directory):
    authority = ec.generate_private_key(ec.SECP256R1())
    ca_name = "Countersign CI issuing CA"
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, ca_name)])
    ca = cert(authority, issuer, ca_name, authority.public_key(), True)
    (directory/"ca.der").write_bytes(ca.public_bytes(serialization.Encoding.DER))
    if sys.platform == "linux":
        sys.path.insert(0,str(ROOT/"examples/demo-integrator"))
        import prepare
        module = prepare.install_identities(directory, (authority,issuer), 3)
        os.environ["COUNTERSIGN_PKCS11_MODULE"] = str(module)
        return json.loads((directory/"fingerprints.json").read_text())
    if sys.platform == "darwin":
        run("clang","-fobjc-arc","-Wno-deprecated-declarations",str(HERE/"macos-key.m"),
            "-framework","Security","-framework","Foundation","-o",str(directory/"gen"))
    result = []
    for _ in range(3):
        name = "CountersignCI-"+uuid.uuid4().hex
        if sys.platform == "darwin":
            point=run(str(directory/"gen"),name,shutil.which("node"),capture_output=True).stdout
            public=ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(),base64.b64decode(point))
        else:
            der=run("pwsh","-NoProfile","-File",str(HERE/"windows-key.ps1"),"generate",name,capture_output=True).stdout
            public=serialization.load_der_public_key(base64.b64decode(der))
        path=directory/(name+".der")
        path.write_bytes(cert(authority,issuer,"Countersign test identity",public,False).public_bytes(serialization.Encoding.DER))
        if sys.platform=="darwin":
            run("security","add-certificates","-k",str(directory/"ci.keychain-db"),str(path))
        else:
            run("pwsh","-NoProfile","-File",str(HERE/"windows-key.ps1"),"install",name,str(path))
        result.append(hashlib.sha256(path.read_bytes()).hexdigest())
    return result

def test(directory, addon):
    if sys.platform == "linux":
        run("gnome-keyring-daemon","--unlock","--components=secrets",
            input=sys.stdin.buffer.read(), stdout=subprocess.DEVNULL)
    elif sys.platform == "darwin":
        # On this fresh CI user, use a dedicated keychain for both enrollment and installed fixtures.
        path = str(directory/"ci.keychain-db")
        password = secrets.token_hex(32)
        run("security","create-keychain","-p",password,path)
        run("security","list-keychains","-d","user","-s",path)
        run("security","default-keychain","-d","user","-s",path)
        run("security","unlock-keychain","-p",password,path)
    for stage in ("create","reopen","retire"):
        run("node",str(HERE/"addon.cjs"),str(addon),stage,str(directory/"pairing-public.json"))
    identities = provision(directory)
    env=dict(os.environ,COUNTERSIGN_CI_ADDON=str(addon),COUNTERSIGN_CI_FINGERPRINTS=json.dumps(identities),
             COUNTERSIGN_CI_CLIENT_ROOT=str(directory/"ca.der"))
    run("cargo","test","--locked","-p","countersign-native","--test","native_mtls","--","--ignored","--nocapture",env=env)

def main():
    if len(sys.argv)==4 and sys.argv[1]=="session":
        test(Path(sys.argv[2]),Path(sys.argv[3]))
        return
    addon=Path(sys.argv[1]).resolve()
    assert addon.suffix == ".node"
    with tempfile.TemporaryDirectory(prefix="cs-native-") as tmp:
        directory=Path(tmp)
        if sys.platform=="linux":
            runtime=directory/"runtime"
            runtime.mkdir(mode=0o700)
            env=dict(os.environ,XDG_DATA_HOME=str(directory/"data"),XDG_RUNTIME_DIR=str(runtime))
            env.pop("GNOME_KEYRING_CONTROL",None)
            subprocess.run(["dbus-run-session","--",sys.executable,__file__,"session",tmp,str(addon)],
                           input=secrets.token_hex(32).encode(),env=env,check=True,timeout=500)
        elif os.environ.get("GITHUB_ACTIONS")=="true":
            test(directory,addon)
        else:
            raise RuntimeError("use a disposable hosted test account on Windows/macOS")
if __name__=="__main__":
    main()
