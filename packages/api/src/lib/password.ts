import { scrypt, randomBytes, timingSafeEqual } from 'node:crypto';

const SALT_LENGTH = 16;
const KEY_LENGTH = 64;
const CURRENT_N = 32768; // 2^15, OWASP recommended minimum

function scryptAsync(password: string, salt: Buffer, keylen: number, N: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scrypt(password, salt, keylen, { N, r: 8, p: 1, maxmem: 64 * 1024 * 1024 }, (err, derived) => {
      if (err) reject(err);
      else resolve(derived);
    });
  });
}

export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(SALT_LENGTH);
  const derived = await scryptAsync(password, salt, KEY_LENGTH, CURRENT_N);
  // Encode N parameter so we can verify old hashes after parameter changes
  return `${CURRENT_N}:${salt.toString('hex')}:${derived.toString('hex')}`;
}

export async function verifyPassword(password: string, storedHash: string): Promise<boolean> {
  const parts = storedHash.split(':');

  let N: number;
  let saltHex: string;
  let keyHex: string;

  if (parts.length === 3) {
    // New format: N:salt:key
    N = parseInt(parts[0], 10);
    saltHex = parts[1];
    keyHex = parts[2];
  } else if (parts.length === 2) {
    // Legacy format: salt:key (used N=16384)
    N = 16384;
    saltHex = parts[0];
    keyHex = parts[1];
  } else {
    return false;
  }

  if (!saltHex || !keyHex || isNaN(N)) return false;
  const salt = Buffer.from(saltHex, 'hex');
  const storedKey = Buffer.from(keyHex, 'hex');
  const derived = await scryptAsync(password, salt, KEY_LENGTH, N);
  return timingSafeEqual(storedKey, derived);
}
