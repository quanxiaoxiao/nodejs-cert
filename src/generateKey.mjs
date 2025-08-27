import { generateKeyPairSync } from 'node:crypto';
import { existsSync, writeFileSync } from 'node:fs';

export default (keyPathname, modulusLength = 2048) => {
  if (!existsSync(keyPathname)) {
    console.log(`🔑 Generating private key: ${keyPathname}`);
    try {
      const { privateKey } = generateKeyPairSync('rsa', {
        modulusLength,
        privateKeyEncoding: {
          type: 'pkcs8',
          format: 'pem',
        },
      });
      writeFileSync(keyPathname, privateKey);
      return existsSync(keyPathname);
    } catch (error) {
      console.error(`❌ Failed to generate private key: ${error.message}`);
      return false;
    }
  }
  return true;
};
