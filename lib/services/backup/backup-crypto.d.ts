/** True when the file begins with the encryption magic (i.e. it is an encrypted archive). */
export declare function isEncryptedArchive(filePath: string): boolean;
/**
 * Encrypts `filePath` in place: reads the plaintext archive, writes `<filePath>.enc`
 * with the encrypted payload, and removes the original. Returns the encrypted path and
 * the original (decrypted) size so the caller can record accurate metadata.
 */
export declare function encryptArchive(filePath: string): {
    encryptedPath: string;
    plaintextSizeBytes: number;
};
/**
 * Decrypts an encrypted archive to `outputPath`. Verifies the GCM tag (throws on
 * tampering/corruption) and writes the recovered plaintext archive.
 */
export declare function decryptArchive(encryptedPath: string, outputPath: string): void;
