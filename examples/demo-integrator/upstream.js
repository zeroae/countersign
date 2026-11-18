// A successful response is evidence that the upstream TLS server accepted the certificate.
import https from 'node:https';
import { readFile } from 'node:fs/promises';
const dir=process.env.DEMO_SECRETS || '/demo';
const [cert,key,ca]=await Promise.all(['site.pem','site.key','client-ca.pem'].map(f=>readFile(dir+'/'+f)));
https.createServer({cert,key,ca,requestCert:true,rejectUnauthorized:true,
  minVersion:'TLSv1.2',maxVersion:'TLSv1.3'},(req,res)=>{
  if(!req.socket.authorized){res.destroy();return;}
  const peer=req.socket.getPeerCertificate();
  res.writeHead(200,{'Content-Type':'application/json'});
  res.end(JSON.stringify({fingerprint:peer.fingerprint256.replaceAll(':','').toLowerCase(),subject:peer.subject.CN}));
}).listen(9444);
