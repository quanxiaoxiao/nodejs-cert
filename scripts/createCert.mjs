import assert from 'node:assert';
import { randomBytes,X509Certificate } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';

import generateCertificate from '../src/generateCertificate.mjs';

const keyPathname = path.resolve(process.cwd(), '_temp', `Quan_${randomBytes(16).toString('hex')}.key`);
const rootCAKeyPathname = path.resolve(process.cwd(), 'cert', 'RootCA.key');
const rootCACertPathname = path.resolve(process.cwd(), 'cert', 'RootCA.pem');

const x509 = new X509Certificate(fs.readFileSync(rootCACertPathname));

const now = Date.now();

const dateTimeStart = new Date(x509.validFrom).valueOf();
const dateTimeEnd = new Date(x509.validTo).valueOf();

assert(now >= dateTimeStart);
assert(now < dateTimeEnd);

const issuers = {
  countryName: 'CN',
  stateName: 'Zhejiang',
  locality: 'East Money Lake',
  organization: 'Quan Inc',
  organizationalUnit: 'quan.org',
  commonName: 'quan.dev',
};
const dnsList = [];
const ipList = [];
const uriList = [];
const dayCount = 356 * 5;

generateCertificate({
  issuers,
  dnsList,
  ipList,
  uriList,
  dayCount,
  rootCAKeyPathname,
  rootCACertPathname,
  keyPathname,
  certPathname: keyPathname.replace(/\.key$/, '.pem'),
});
