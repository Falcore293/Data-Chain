// public/js/crypto-client.js
// Client-side mirror of utils/crypto.js on the server. Uses node-forge so
// the PBKDF2 / AES-GCM / RSA-OAEP implementations line up byte-for-byte
// with Node's built-in crypto module. Nothing decrypted here ever leaves
// the browser.

const PBKDF2_ITERATIONS = 100000;
const PBKDF2_KEYLEN = 32;

/**
 * Unlocks a downloaded .datachain-key.json bundle with the account
 * password, returning the plaintext RSA private key as a PEM string.
 * Throws if the password is wrong (GCM auth tag won't verify).
 */
function decryptPrivateKeyBundle(bundle, password) {
  const salt = forge.util.decode64(bundle.salt);
  const iv = forge.util.decode64(bundle.iv);
  const authTag = forge.util.decode64(bundle.authTag);
  const ciphertext = forge.util.decode64(bundle.ciphertext);

  const passwordBytes = forge.util.encodeUtf8(password);
  const key = forge.pkcs5.pbkdf2(passwordBytes, salt, PBKDF2_ITERATIONS, PBKDF2_KEYLEN, forge.md.sha256.create());

  const decipher = forge.cipher.createDecipher('AES-GCM', key);
  decipher.start({ iv, tagLength: 128, tag: forge.util.createBuffer(authTag) });
  decipher.update(forge.util.createBuffer(ciphertext));
  const ok = decipher.finish();

  if (!ok) {
    throw new Error('Wrong password, or the key file does not match this account.');
  }

  return forge.util.decodeUtf8(decipher.output.getBytes());
}

/**
 * Unwraps the AES file key using the RSA private key (RSA-OAEP / SHA-256,
 * matching crypto.constants.RSA_PKCS1_OAEP_PADDING + oaepHash: 'sha256'
 * on the server).
 */
function unwrapAESKey(privateKeyPem, encryptedKeyBase64) {
  const privateKey = forge.pki.privateKeyFromPem(privateKeyPem);
  const encryptedKeyBytes = forge.util.decode64(encryptedKeyBase64);
  return privateKey.decrypt(encryptedKeyBytes, 'RSA-OAEP', {
    md: forge.md.sha256.create(),
    mgf1: { md: forge.md.sha256.create() }
  });
}

/**
 * Decrypts the actual file with the unwrapped AES key (AES-256-GCM,
 * matching the server's encryptFileEnvelope). Returns a Uint8Array of
 * the original plaintext file bytes.
 */
function decryptFile(encryptedFileBase64, ivBase64, authTagBase64, aesKeyBytes) {
  const iv = forge.util.decode64(ivBase64);
  const authTag = forge.util.decode64(authTagBase64);
  const ciphertext = forge.util.decode64(encryptedFileBase64);

  const decipher = forge.cipher.createDecipher('AES-GCM', aesKeyBytes);
  decipher.start({ iv, tagLength: 128, tag: forge.util.createBuffer(authTag) });
  decipher.update(forge.util.createBuffer(ciphertext));
  const ok = decipher.finish();

  if (!ok) {
    throw new Error('File integrity check failed — the auth tag did not verify.');
  }

  const binaryStr = decipher.output.getBytes();
  const bytes = new Uint8Array(binaryStr.length);
  for (let i = 0; i < binaryStr.length; i++) bytes[i] = binaryStr.charCodeAt(i);
  return bytes;
}

/** SHA-256 of a Uint8Array, as a hex string — used for the integrity check. */
function sha256Hex(uint8Array) {
  const buffer = forge.util.createBuffer();
  for (let i = 0; i < uint8Array.length; i++) buffer.putByte(uint8Array[i]);
  return forge.md.sha256.create().update(buffer.getBytes()).digest().toHex();
}
