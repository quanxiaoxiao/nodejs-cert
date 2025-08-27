import { execSync } from 'node:child_process';
import { existsSync } from 'node:fs';

import generateIssuers from './generateIssuers.mjs';

const checkFileExistence = ({
  rootCAKeyPathname,
  rootCACertPathname,
  configPathname,
}) => {
  if (existsSync(rootCACertPathname)) {
    throw new Error(`root cert \`${rootCACertPathname}\` already exist`);
  }

  if (!existsSync(rootCAKeyPathname)) {
    throw new Error(`key \`${rootCAKeyPathname}\` not found`);
  }

  if (configPathname && !existsSync(configPathname)) {
    throw new Error(`config file \`${configPathname}\` not found`);
  }
};

export default ({
  dayCount = 365,
  issuers,
  rootCAKeyPathname,
  rootCACertPathname,
  configPathname,
  requestExtName,
}) => {
  try {
    checkFileExistence({
      rootCAKeyPathname,
      rootCACertPathname,
      configPathname,
    });
  } catch (error) {
    console.error(`❌ Failed to generate private key: ${error.message}`);
    return false;
  }

  if (dayCount == null || dayCount <= 0) {
    console.error('❌ dayCount must be a positive number');
    return false;
  }

  const command = [
    'openssl',
    'req',
    '-new',
    '-x509',
    '-nodes',
    '-sha256',
    '-key',
    rootCAKeyPathname,
    `-days ${dayCount}`,
    `-subj "${generateIssuers(issuers)}"`,
    `-out ${rootCACertPathname}`,
  ];

  if (configPathname) {
    command.push(`-config ${configPathname}`);
  }

  if (requestExtName) {
    command.push(`-reqexts ${requestExtName}`);
  }

  execSync(command.join(' '), { stdio: 'pipe' });
  if (!existsSync(rootCACertPathname)) {
    console.error(`❌ Failed to generate Root Certificate: ${rootCACertPathname}`);
    return false;
  }
  console.log(`✅ Root Certificate generated successfully: ${rootCACertPathname}`);
  return true;
};
