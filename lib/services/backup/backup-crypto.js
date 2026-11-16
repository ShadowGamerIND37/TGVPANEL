"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.isEncryptedArchive = isEncryptedArchive;
exports.encryptArchive = encryptArchive;
exports.decryptArchive = decryptArchive;
const crypto_1 = __importDefault(require("crypto"));
const fs_1 = __importDefault(require("fs"));
const path_1 = __importDefault(require("path"));
const crypto_vault_1 = require("../../security/crypto-vault");
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
function credentialKey() {
    const hex = (0, crypto_vault_1.getSecretBundle)().credentialKeyHex;
    const key = Buffer.from(hex, 'hex');
    if (key.length !== 32) {
        throw new Error('Backup encryption requires a 256-bit credential key.');
    }
    return key;
}
/** True when the file begins with the encryption magic (i.e. it is an encrypted archive). */
function isEncryptedArchive(filePath) {
    try {
        const fd = fs_1.default.openSync(filePath, 'r');
        try {
            const header = Buffer.alloc(MAGIC.length);
            const bytesRead = fs_1.default.readSync(fd, header, 0, MAGIC.length, 0);
            return bytesRead === MAGIC.length && header.equals(MAGIC);
        }
        finally {
            fs_1.default.closeSync(fd);
        }
    }
    catch {
        return false;
    }
}
/**
 * Encrypts `filePath` in place: reads the plaintext archive, writes `<filePath>.enc`
 * with the encrypted payload, and removes the original. Returns the encrypted path and
 * the original (decrypted) size so the caller can record accurate metadata.
 */
function encryptArchive(filePath) {
    const plaintext = fs_1.default.readFileSync(filePath);
    const iv = crypto_1.default.randomBytes(IV_LENGTH);
    const cipher = crypto_1.default.createCipheriv('aes-256-gcm', credentialKey(), iv);
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    const encryptedPath = `${filePath}.enc`;
    const out = Buffer.alloc(HEADER_LENGTH + ciphertext.length);
    MAGIC.copy(out, 0);
    iv.copy(out, MAGIC.length);
    tag.copy(out, MAGIC.length + IV_LENGTH);
    ciphertext.copy(out, HEADER_LENGTH);
    fs_1.default.writeFileSync(encryptedPath, out, { mode: 0o600 });
    fs_1.default.unlinkSync(filePath);
    return { encryptedPath, plaintextSizeBytes: plaintext.length };
}
/**
 * Decrypts an encrypted archive to `outputPath`. Verifies the GCM tag (throws on
 * tampering/corruption) and writes the recovered plaintext archive.
 */
function decryptArchive(encryptedPath, outputPath) {
    const data = fs_1.default.readFileSync(encryptedPath);
    if (data.length < HEADER_LENGTH || !data.subarray(0, MAGIC.length).equals(MAGIC)) {
        throw new Error(`File ${encryptedPath} is not a TGVPANEL encrypted backup archive.`);
    }
    const iv = data.subarray(MAGIC.length, MAGIC.length + IV_LENGTH);
    const tag = data.subarray(MAGIC.length + IV_LENGTH, HEADER_LENGTH);
    const ciphertext = data.subarray(HEADER_LENGTH);
    const decipher = crypto_1.default.createDecipheriv('aes-256-gcm', credentialKey(), iv);
    decipher.setAuthTag(tag);
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    fs_1.default.mkdirSync(path_1.default.dirname(outputPath), { recursive: true });
    fs_1.default.writeFileSync(outputPath, plaintext, { mode: 0o600 });
}
