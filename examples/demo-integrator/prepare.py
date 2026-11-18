"""Create a fresh local demo PKI and three installed PKCS#11 client identities."""
import argparse
import ctypes
import datetime as dt
import json
import os
from pathlib import Path
import secrets
import subprocess

from asn1crypto.core import OctetString
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
import pkcs11
from pkcs11.util.ec import encode_named_curve_parameters


def issue(issuer, subject, public_key, *, ca=False, names=()):
    now = dt.datetime.now(dt.timezone.utc)
    key, parent = issuer
    builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(parent)
               .public_key(public_key).serial_number(x509.random_serial_number())
               .not_valid_before(now - dt.timedelta(minutes=1)).not_valid_after(now + dt.timedelta(days=2))
               .add_extension(x509.BasicConstraints(ca, 0 if ca else None), critical=True)
               .add_extension(x509.KeyUsage(True, False, False, False, False, ca, ca, False, False), critical=True))
    if not ca:
        usage = ExtendedKeyUsageOID.SERVER_AUTH if names else ExtendedKeyUsageOID.CLIENT_AUTH
        builder = builder.add_extension(x509.ExtendedKeyUsage([usage]), critical=False)
    if names:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False)
    return builder.sign(key,hashes.SHA256())


def name(value):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, value)])


def authority(directory, stem):
    key = ec.generate_private_key(ec.SECP256R1())
    issuer = key, name('Countersign demo ' + stem)
    cert = issue(issuer,issuer[1],key.public_key(),ca=True)
    (directory/(stem+'.pem')).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return issuer


def server_identity(directory,issuer,stem,names):
    key=ec.generate_private_key(ec.SECP256R1())
    cert=issue(issuer,name(stem),key.public_key(),names=names)
    (directory/(stem+'.key')).write_bytes(key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    (directory/(stem+'.pem')).write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def install_identities(directory,client_ca,count):
    token_dir=directory/'tokens'
    token_dir.mkdir()
    module=next(Path('/usr/lib').glob('*/softhsm/libsofthsm2.so'))
    config=directory/'softhsm.conf'
    config.write_text('directories.tokendir = '+str(token_dir)+'\nobjectstore.backend = file\nlog.level = ERROR\n')
    os.environ['SOFTHSM2_CONF']=str(config)
    so_pin=secrets.token_hex(20).encode()
    user_pin=secrets.token_hex(20)
    library=pkcs11.lib(str(module))
    [slot]=library.get_slots()
    assert not slot.get_token().label.strip()
    # Only the freshly created, empty SoftHSM store above is visible to this process.
    rv=ctypes.CDLL(str(module)).C_InitToken(ctypes.c_ulong(slot.slot_id),so_pin,len(so_pin),
                                           b'Countersign demo'.ljust(32))
    if rv: raise RuntimeError('Failed to initialize disposable token')
    token=library.get_token(token_label='Countersign demo')
    with token.open(rw=True,so_pin=so_pin.decode()) as session:
        session.init_pin(user_pin)
    subprocess.run(['secret-tool','store','--label=Countersign demo token','application','Countersign',
                    'kind','website-token','token','Countersign demo'],input=user_pin.encode(),check=True)
    fingerprints=[]
    A=pkcs11.Attribute
    with token.open(rw=True,user_pin=user_pin) as session:
        domain=session.create_domain_parameters(pkcs11.KeyType.EC,{A.EC_PARAMS:encode_named_curve_parameters('secp256r1')},local=True)
        for index in range(1,count+1):
            kid=bytes([index])
            public,private=domain.generate_keypair(id=kid,label=f'demo-{index}',store=True,
                private_template={A.SENSITIVE:True,A.EXTRACTABLE:False,A.SIGN:True})
            assert not private[A.EXTRACTABLE]
            point=OctetString.load(public[A.EC_POINT]).native
            key=ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(),point)
            # An identical name exercises the picker's fingerprint disambiguation.
            cert=issue(client_ca,name('Demo user'),key)
            session.create_object({A.CLASS:pkcs11.ObjectClass.CERTIFICATE,A.CERTIFICATE_TYPE:pkcs11.CertificateType.X_509,
                A.TOKEN:True,A.PRIVATE:False,A.ID:kid,A.LABEL:f'demo-{index}',A.SUBJECT:cert.subject.public_bytes(),
                A.VALUE:cert.public_bytes(serialization.Encoding.DER)})
            fingerprints.append(cert.fingerprint(hashes.SHA256()).hex())
    (directory/'fingerprints.json').write_text(json.dumps(fingerprints))
    return module


def prepare(path, count=3):
    directory=path.resolve()
    os.umask(0o077)
    directory.mkdir(mode=0o700)  # refuse to overwrite an existing demo
    infra=authority(directory,'ca')
    client=authority(directory,'client-ca')
    for stem,names in [('site',['site.test']),('integrator',['localhost','integrator']),('broker',['localhost','broker'])]:
        server_identity(directory,infra,stem,names)
    for filename in ['backend.token','login.secret','workload.hmac','admin.token']:
        (directory/filename).write_text(secrets.token_urlsafe(32))
    module=install_identities(directory,client,count)
    print('Fixture directory:',directory)
    print('PKCS#11 module:',module)
    return directory


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('directory',type=Path)
    prepare(parser.parse_args().directory)
