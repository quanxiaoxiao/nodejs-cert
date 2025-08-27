import { execSync } from 'node:child_process';
import { existsSync } from 'node:fs';

import generateIssuers from './generateIssuers.mjs';

export default ({
  dayCount,
  issuers,
  rootCAKeyPathname,
  rootCACertPathname,
  configPathname,
  requestExtName,
}) => {
  if (existsSync(rootCACertPathname)) {
    console.log(`generateRootCert fail, \`${rootCACertPathname}\` already exist`);
    process.exit(1);
  }
  if (!existsSync(rootCAKeyPathname)) {
    console.log(`generateRootCert fail, \`${rootCACertPathname}\` is not exist`);
    process.exit(1);
  }
  if (configPathname && !existsSync(configPathname)) {
    console.log(`generateRootCert fail, \`${configPathname}\` is not exist`);
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

  execSync(command.join(' '));
  if (existsSync(rootCACertPathname)) {
    console.log(`\`${rootCACertPathname}\` generateRootCert success`);
  }
};
