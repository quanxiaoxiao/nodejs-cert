import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';

import generateKey from '../src/generateKey.mjs';
import generateRootCert from '../src/generateRootCert.mjs';

const rootKeyPathname = path.resolve(process.cwd(), '_temp', `Root_${crypto.randomBytes(16).toString('hex')}.key`);

generateKey(rootKeyPathname);

const requestExtName = 'v3_ca';

const configPathname = rootKeyPathname.replace(/\.key$/, '.cnf');

fs.writeFileSync(
  configPathname,
  `[ ${requestExtName} ]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage         = critical, keyCertSign, cRLSign
subjectKeyIdentifier  = hash
authorityKeyIdentifier = keyid:always,issuer`,
);

generateRootCert({
  dayCount: 365,
  issuers: {
    countryName: 'CN',
    stateName: 'Zhejiang',
    locality: 'East Money Lake',
    organization: 'Quan Inc',
    organizationalUnit: 'quan.org',
    commonName: 'quan.dev',
  },
  configPathname,
  rootCAKeyPathname: rootKeyPathname,
  rootCACertPathname: rootKeyPathname.replace(/\.key$/, '.pem'),
  requestExtName,
});
