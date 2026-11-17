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
from cryptography.hazmat.primitives.asymmetric import ec, rsa
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

def extra_linux_identities(module, authority, issuer):
    """Install a P-384 and an RSA-2048 key in the same disposable token."""
    import pkcs11
    from pkcs11.util.ec import encode_named_curve_parameters
    from asn1crypto.core import OctetString
    pin = run("secret-tool","lookup","application","Countersign","kind","website-token","token","Countersign demo",
              capture_output=True).stdout.decode().rstrip("\n")
    token = pkcs11.lib(str(module)).get_token(token_label="Countersign demo")
    A = pkcs11.Attribute
    fingerprints = []
    with token.open(rw=True,user_pin=pin) as session:
        for alg in ("p384","rsa"):
            kid = alg.encode()
            options = dict(id=kid,label=alg,store=True,private_template={A.SENSITIVE: True,A.EXTRACTABLE: False,A.SIGN: True})
            if alg=="p384":
                domain=session.create_domain_parameters(pkcs11.KeyType.EC,{A.EC_PARAMS:encode_named_curve_parameters("secp384r1")},local=True)
                public, private = domain.generate_keypair(**options)
                point = OctetString.load(public[A.EC_POINT]).native
                key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(),point)
            else:
                public, private = session.generate_keypair(pkcs11.KeyType.RSA,2048,**options)
                n = int.from_bytes(public[A.MODULUS],"big")
                e = int.from_bytes(public[A.PUBLIC_EXPONENT],"big")
                key = rsa.RSAPublicNumbers(e,n).public_key()
            assert not private[A.EXTRACTABLE]
            certificate=cert(authority,issuer,"Alternate native identity",key,False)
            session.create_object({A.CLASS:pkcs11.ObjectClass.CERTIFICATE,A.CERTIFICATE_TYPE:pkcs11.CertificateType.X_509,
                A.TOKEN:True,A.PRIVATE:False,A.ID:kid,A.LABEL:alg,A.SUBJECT:certificate.subject.public_bytes(),
                A.VALUE:certificate.public_bytes(serialization.Encoding.DER)})
            fingerprints.append(certificate.fingerprint(hashes.SHA256()).hex())
    return fingerprints

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
        return json.loads((directory/"fingerprints.json").read_text()) + extra_linux_identities(module,authority,issuer)
    result = []
    for alg in ("p256","p256","p256","p384","rsa"):
        name = "CountersignCI-"+uuid.uuid4().hex
        if sys.platform == "darwin":
            point=run("node","-e","process.stdout.write(require(process.argv[1]).generateWebsiteKey(process.argv[2],process.argv[3]))",
                      str(directory/"macos-fixture.node"),name,alg,capture_output=True).stdout
            if alg=="rsa":
                public=serialization.load_der_public_key(base64.b64decode(point))
            else:
                curve = ec.SECP384R1() if alg=="p384" else ec.SECP256R1()
                public=ec.EllipticCurvePublicKey.from_encoded_point(curve,base64.b64decode(point))
        else:
            der=run("pwsh","-NoProfile","-File",str(HERE/"windows-key.ps1"),"generate",name,"-Algorithm",alg,capture_output=True).stdout
            public=serialization.load_der_public_key(base64.b64decode(der))
        path=directory/(name+".der")
        path.write_bytes(cert(authority,issuer,"Countersign test identity",public,False).public_bytes(serialization.Encoding.DER))
        if sys.platform=="darwin":
            run("security","add-certificates","-k",str(directory/"ci.keychain-db"),str(path))
        else:
            run("pwsh","-NoProfile","-File",str(HERE/"windows-key.ps1"),"install",name,str(path),"-Algorithm",alg)
        result.append(hashlib.sha256(path.read_bytes()).hexdigest())
    return result

def test(directory, addon):
    if sys.platform == "linux":
        run("gnome-keyring-daemon","--unlock","--components=secrets",
            input=sys.stdin.buffer.read(), stdout=subprocess.DEVNULL)
    elif sys.platform == "darwin":
        node_headers=Path(shutil.which("node")).resolve().parent.parent/"include/node"
        run("clang","-bundle","-undefined","dynamic_lookup","-fobjc-arc","-Wno-deprecated-declarations",
            "-I"+str(node_headers),str(HERE/"macos-key.m"),"-framework","Security","-framework","Foundation",
            "-o",str(directory/"macos-fixture.node"))
        # On this fresh CI user, use a dedicated keychain for both enrollment and installed fixtures.
        path = str(directory/"ci.keychain-db")
        password = secrets.token_hex(32)
        run("security","create-keychain","-p",password,path)
        run("security","list-keychains","-d","user","-s",path)
        run("security","default-keychain","-d","user","-s",path)
        run("security","unlock-keychain","-p",password,path)
    for stage in ("create","reopen","retire"):
        record = directory/"pairing-public.json"
        run("node",str(HERE/"addon.cjs"),str(addon),stage,str(record))
        if stage == "create" and sys.platform=="darwin":
            guard = directory/"macos-fixture.node"
            run("security","lock-keychain",path)
            run("node",str(HERE/"addon.cjs"),str(addon),"locked",str(record),str(guard))
            run("security","unlock-keychain","-p",password,path)
        if stage == "create" and sys.platform=="win32":
            run("pwsh","-NoProfile","-File",str(HERE/"windows-cold.ps1"),str(addon),
                str(HERE/"addon.cjs"),str(record))
    identities = provision(directory)
    env=dict(os.environ,COUNTERSIGN_CI_ADDON=str(addon),COUNTERSIGN_CI_FINGERPRINTS=json.dumps(identities),
             COUNTERSIGN_CI_CLIENT_ROOT=str(directory/"ca.der"))
    if sys.platform == "darwin":
        env["COUNTERSIGN_CI_NO_UI"] = str(directory/"macos-fixture.node")
    run("cargo","test","--locked","-p","countersign-native","--test","native_mtls","--","--ignored","--nocapture",env=env)

def main():
    if len(sys.argv)==4 and sys.argv[1]=="session":
        test(Path(sys.argv[2]),Path(sys.argv[3]))
        return
    addon=Path(sys.argv[1]).resolve()
    assert addon.suffix == ".node"
    binary = addon.read_bytes()
    for forbidden in (b"installFixtureKey", b"activateFixtureScope", b"fixtureSign", b"exportPrivateKey",
                      b"genericSignBytes", b"generateWebsiteKey", b"COUNTERSIGN_CI_NO_UI", b"COUNTERSIGN_CI_CLIENT_ROOT", b"COUNTERSIGN_CI_FINGERPRINTS"):
        if forbidden in binary:
            raise RuntimeError("fixture or general-signing entry point in product artifact")
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
