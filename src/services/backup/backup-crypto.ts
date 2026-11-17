import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { getSecretBundle } from '../../security/crypto-vault';

/**
 * Backup archive encryption-at-rest.
 *
 * Local LXC backup archives (tar.gz) are encrypted on disk with AES-256-GCM using the
 * panel's existing credential key (`getSecretBundle().credentialKeyHex`). The encrypted
 * file is self-describing so the restore/verify/delete paths can detect and decrypt it
 * without extra metadata lookups beyond the DB `encrypted` flag.
 *
 * File format (all binary, big-endian where relevant):
 *   magic    : 8 bytes  "TGVENC1"
 *   iv       : 12 bytes (AES-GCM standard 96-bit IV)
 *   tag      : 16 bytes (GCM authentication tag)
 *   ciphertext: remaining bytes
 *
 * AES-GCM's authentication tag already guarantees encrypted-file integrity, so a
 * tampered archive fails to decrypt. The stored SHA-256 remains the checksum of the
 * *decrypted* content so restore can verify the recovered archive independently.
 */

const MAGIC = Buffer.from('TGVENC1', 'ascii');
const IV_LENGTH = 12;
const TAG_LENGTH = 16;
const HEADER_LENGTH = MAGIC.length + IV_LENGTH + TAG_LENGTH;

function credentialKey(): Buffer {
  const hex = getSecretBundle().credentialKeyHex;
  const key = Buffer.from(hex, 'hex');
  if (key.length !== 32) {
    throw new Error('Backup encryption requires a 256-bit credential key.');
  }
  return key;
}

/** True when the file begins with the encryption magic (i.e. it is an encrypted archive). */
export function isEncryptedArchive(filePath: string): boolean {
  try {
    const fd = fs.openSync(filePath, 'r');
    try {
      const header = Buffer.alloc(MAGIC.length);
      const bytesRead = fs.readSync(fd, header, 0, MAGIC.length, 0);
      return bytesRead === MAGIC.length && header.equals(MAGIC);
    } finally {
      fs.closeSync(fd);
    }
  } catch {
    return false;
  }
}

/**
 * Encrypts `filePath` in place: reads the plaintext archive, writes `<filePath>.enc`
 * with the encrypted payload, and removes the original. Returns the encrypted path and
 * the original (decrypted) size so the caller can record accurate metadata.
 */
export function encryptArchive(filePath: string): { encryptedPath: string; plaintextSizeBytes: number } {
  const plaintext = fs.readFileSync(filePath);
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv('aes-256-gcm', credentialKey(), iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();

  const encryptedPath = `${filePath}.enc`;
  const out = Buffer.alloc(HEADER_LENGTH + ciphertext.length);
  MAGIC.copy(out, 0);
  iv.copy(out, MAGIC.length);
  tag.copy(out, MAGIC.length + IV_LENGTH);
  ciphertext.copy(out, HEADER_LENGTH);
  fs.writeFileSync(encryptedPath, out, { mode: 0o600 });
  fs.unlinkSync(filePath);
  return { encryptedPath, plaintextSizeBytes: plaintext.length };
}

/**
 * Decrypts an encrypted archive to `outputPath`. Verifies the GCM tag (throws on
 * tampering/corruption) and writes the recovered plaintext archive.
 */
export function decryptArchive(encryptedPath: string, outputPath: string): void {
  const data = fs.readFileSync(encryptedPath);
  if (data.length < HEADER_LENGTH || !data.subarray(0, MAGIC.length).equals(MAGIC)) {
    throw new Error(`File ${encryptedPath} is not a TGVPANEL encrypted backup archive.`);
  }
  const iv = data.subarray(MAGIC.length, MAGIC.length + IV_LENGTH);
  const tag = data.subarray(MAGIC.length + IV_LENGTH, HEADER_LENGTH);
  const ciphertext = data.subarray(HEADER_LENGTH);

  const decipher = crypto.createDecipheriv('aes-256-gcm', credentialKey(), iv);
  decipher.setAuthTag(tag);
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.writeFileSync(outputPath, plaintext, { mode: 0o600 });
}
