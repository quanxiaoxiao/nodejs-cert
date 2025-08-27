import { execSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import {
  existsSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { resolve } from 'node:path';

import generateIssuers from './generateIssuers.mjs';
import generateKey from './generateKey.mjs';

const validateInputs = ({
  dayCount,
  issuers,
  rootCAKeyPathname,
  rootCACertPathname,
  keyPathname,
  certPathname,
}) => {
  const requiredFields = [
    { field: dayCount, name: 'dayCount', type: 'number' },
    { field: issuers, name: 'issuers', type: 'object' },
    { field: rootCAKeyPathname, name: 'rootCAKeyPathname', type: 'string' },
    { field: rootCACertPathname, name: 'rootCACertPathname', type: 'string' },
    { field: keyPathname, name: 'keyPathname', type: 'string' },
    { field: certPathname, name: 'certPathname', type: 'string' },
  ];

  for (const { field, name, type } of requiredFields) {
    if (typeof field !== type || (type === 'string' && !field.trim())) {
      console.error(`❌ Invalid ${name}: expected ${type}, got ${typeof field}`);
      return false;
    }
  }

  if (dayCount <= 0) {
    console.error('❌ dayCount must be a positive number');
    return false;
  }

  return true;
};

const checkRootCertFiles = (rootCACertPathname, rootCAKeyPathname) => {
  if (!existsSync(rootCACertPathname)) {
    console.error(`❌ Root certificate not found: ${rootCACertPathname}`);
    return false;
  }

  if (!existsSync(rootCAKeyPathname)) {
    console.error(`❌ Root certificate key not found: ${rootCAKeyPathname}`);
    return false;
  }

  return true;
};

const generateCertRequest = (keyPathname, issuers) => {
  const certReqPathname = resolve(process.cwd(), `${randomBytes(12).toString('hex')}.csr`);

  try {
    const subjectString = generateIssuers(issuers);

    const command = [
      'openssl', 'req', '-new',
      '-key', keyPathname,
      '-subj', `"${subjectString}"`,
      '-out', certReqPathname,
    ];

    execSync(command.join(' '), { stdio: 'pipe' });

    if (!existsSync(certReqPathname)) {
      throw new Error(`Certificate request file was not created: ${certReqPathname}`);
    }

    return certReqPathname;
  } catch (error) {
    console.error(`❌ Failed to create certificate request: ${error.message}`);
    if (existsSync(certReqPathname)) {
      unlinkSync(certReqPathname);
    }
    return null;
  }
};

const generateExtensionFile = ({ dnsList, ipList, uriList }) => {
  const extFilePathname = resolve(process.cwd(), `${randomBytes(12).toString('hex')}.conf`);

  const extContentList = [
    'authorityKeyIdentifier=keyid,issuer',
    'basicConstraints=CA:FALSE',
    'keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment',
    'extendedKeyUsage = serverAuth, clientAuth, codeSigning, emailProtection',
  ];

  try {
    const dnsEntries = (dnsList || [])
      .filter(dns => dns && typeof dns === 'string')
      .map((dns, i) => `DNS.${i + 1} = ${dns.trim()}`);

    const ipEntries = (ipList || [])
      .filter(ip => ip && typeof ip === 'string')
      .map((ip, i) => `IP.${i + 1} = ${ip.trim()}`);

    const uriEntires = (uriList || [])
      .filter(uri=> uri && typeof uri === 'string')
      .map((uri, i) => `URI.${i + 1} = ${uri.trim()}`);

    if (dnsEntries.length !== 0
      || ipEntries.length !== 0
      || uriEntires.length !== 0
    ) {
      extContentList.push('subjectAltName = @alt_names');
      extContentList.push('');
      extContentList.push('[alt_names]');
      if (dnsEntries.length > 0) {
        extContentList.push(...dnsEntries);
      }
      if (ipEntries.length > 0) {
        extContentList.push(...ipEntries);
      }
      if (uriEntires.length > 0) {
        extContentList.push(...uriEntires);
      }
    }

    const extFileContent = extContentList.join('\n');

    writeFileSync(extFilePathname, extFileContent, 'utf8');
    return extFilePathname;
  } catch (error) {
    console.error(`❌ Failed to create extension file: ${error.message}`);
    if (existsSync(extFilePathname)) {
      unlinkSync(extFilePathname);
    }
    return null;
  }
};

const cleanupTempFiles = (filenames) => {
  for (const filename of filenames) {
    if (filename && existsSync(filename)) {
      try {
        unlinkSync(filename);
      } catch (error) {
        console.warn(`⚠️  Failed to cleanup temporary file ${filename}: ${error.message}`);
      }
    }
  }
};

const generateCert = ({
  certReqPathname,
  rootCACertPathname,
  rootCAKeyPathname,
  dayCount,
  certPathname,
  extFilePathname,
}) => {
  try {
    const command = [
      'openssl', 'x509', '-req',
      '-in', certReqPathname,
      '-CA', rootCACertPathname,
      '-CAkey', rootCAKeyPathname,
      '-days', dayCount.toString(),
      '-sha256',
      '-out', certPathname,
      '-CAcreateserial',
    ];

    if (extFilePathname) {
      command.push('-extfile', extFilePathname);
    }

    execSync(command.join(' '), { stdio: 'pipe' });
    return true;
  } catch (error) {
    console.error(`❌ Failed to generate certificate: ${error.message}`);
    return false;
  }
};

export default (input) => {
  if (!validateInputs(input)) {
    return false;
  }
  const {
    dayCount,
    issuers,
    dnsList,
    ipList,
    uriList,
    rootCAKeyPathname,
    rootCACertPathname,
    keyPathname,
    certPathname,
  } = input;
  if (!checkRootCertFiles(rootCACertPathname, rootCAKeyPathname)) {
    return false;
  }

  if (!generateKey(keyPathname)) {
    return false;
  }

  let certReqPathname = null;

  let extFilePathname;

  try {
    certReqPathname = generateCertRequest(keyPathname, issuers);
    if (!certReqPathname) {
      throw new Error('Failed to generate certificate request');
    }

    extFilePathname = generateExtensionFile({ dnsList, ipList, uriList });

    const success = generateCert({
      certReqPathname,
      rootCACertPathname,
      rootCAKeyPathname,
      dayCount,
      certPathname,
      extFilePathname,
    });

    if (success && existsSync(certPathname)) {
      console.log(`✅ Certificate generated successfully: ${certPathname}`);
      return true;
    }
    console.error(`❌ Failed to generate certificate: ${certPathname}`);
    return false;

  } catch (error) {
    console.error(`❌ Certificate generation failed: ${error.message}`);
    return false;
  } finally {
    cleanupTempFiles([certReqPathname, extFilePathname]);
  }
};
