'use strict';
// Genuine TLS1.3/mTLS/RS256 health probe for the verified official node image.
const fs = require('node:fs');
const https = require('node:https');
const crypto = require('node:crypto');
const {execFileSync} = require('node:child_process');
try {
  const obj = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
  const payload = JSON.parse(Buffer.from(obj.secret, 'base64').toString('utf8'));
  const normalize = value => value.replace(/\\n/g, '\n').replace(/\r\n/g, '\n').trim() + '\n';
  const cert = new crypto.X509Certificate(normalize(payload.nodeCertPem));
  const header = Buffer.from(JSON.stringify({alg: 'RS256', typ: 'JWT'})).toString('base64url');
  const now = Math.floor(Date.now() / 1000);
  const body = Buffer.from(JSON.stringify({iat: now, exp: now + 60})).toString('base64url');
  const unsigned = header + '.' + body;
  const signature = crypto.sign('RSA-SHA256', Buffer.from(unsigned), normalize(obj.credentials.jwtPrivateKeyPem)).toString('base64url');
  const stockVersion = execFileSync('/usr/local/bin/xray', ['version'], {encoding: 'utf8'});
  if (!/^Xray 26\.11\.9\b/.test(stockVersion)) process.exit(1);
  const request = https.request({
    host: '127.0.0.1', port: obj.port, path: '/node/xray/healthcheck',
    minVersion: 'TLSv1.3', rejectUnauthorized: true,
    ca: normalize(payload.caCertPem), cert: normalize(obj.credentials.clientCertPem),
    key: normalize(obj.credentials.clientKeyPem),
    // Official node cert has random CN/no SAN: verify CA AND exact node cert.
    checkServerIdentity: (_name, peer) => peer.raw && peer.raw.equals(cert.raw) ? undefined : new Error('certificate pin mismatch'),
    headers: {Authorization: 'Bearer ' + unsigned + '.' + signature}, timeout: 6000,
  }, response => {
    let data = '';
    response.on('data', chunk => { data += chunk; if (data.length > 1024 * 1024) request.destroy(); });
    response.on('end', () => {
      try {
        const health = JSON.parse(data).response;
        process.exit(response.statusCode === 200 && health.isAlive === true && health.nodeVersion === '3.4.5' && health.xrayVersion === '26.11.9' ? 0 : 1);
      } catch { process.exit(1); }
    });
    response.on('error', () => process.exit(1));
  });
  request.on('timeout', () => request.destroy());
  request.on('error', () => process.exit(1));
  request.end();
} catch { process.exit(1); }
