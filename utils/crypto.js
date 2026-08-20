// ============================================================================
// utils/crypto.js — Cryptography Module (Encryption & Hashing)
// ============================================================================
//
// WHAT IS THIS FILE?
// ------------------
// This file handles ALL cryptographic operations in Data Chain:
//   1. Generating RSA key pairs (public + private keys)
//   2. Encrypting private keys with user passwords (PBKDF2 + AES-GCM)
//   3. Hashing files with SHA-256 (creating digital fingerprints)
//   4. Encrypting files using "envelope encryption" (AES + RSA combined)
//   5. Multi-recipient encryption for group file sharing
//
// WHY IS ENCRYPTION IMPORTANT?
// ----------------------------
// Encryption ensures that even if someone gains access to the server or
// database, they CANNOT read the actual file contents. Files are encrypted
// BEFORE being stored on disk, and can ONLY be decrypted by the intended
// recipient who holds the matching private key.
//
// KEY CRYPTOGRAPHIC CONCEPTS USED:
// ---------------------------------
//  • Asymmetric Encryption (RSA):
//    Two keys — a PUBLIC key (shared openly) and a PRIVATE key (kept secret).
//    Data encrypted with the public key can ONLY be decrypted with the
//    matching private key. Think of it like a mailbox: anyone can drop mail
//    in (public key = the slot), but only the owner can open it (private key).
//
//  • Symmetric Encryption (AES-256-GCM):
//    One key encrypts AND decrypts. Much faster than RSA, but both parties
//    need the same key. AES-256 means a 256-bit key — practically
//    unbreakable with current technology. GCM mode adds "authentication",
//    meaning it can detect if the encrypted data was tampered with.
//
//  • Envelope Encryption (RSA + AES combined):
//    RSA can only encrypt small amounts of data (< key size). AES can
//    encrypt anything but requires securely sharing the key. Solution:
//    encrypt the FILE with a random AES key (fast, any size), then encrypt
//    that small AES key with the recipient's RSA public key (secure sharing).
//    This gives you the best of both worlds.
//
//  • PBKDF2 (Password-Based Key Derivation Function 2):
//    Converts a human-readable password into a cryptographic key. It
//    intentionally runs the hash function 100,000 times to make brute-force
//    password guessing extremely slow (called "key stretching").
//
//  • SHA-256 Hashing:
//    Creates a unique 64-character fingerprint of file contents. Used for
//    integrity verification (did the file change?) and blockchain logging.
// ============================================================================

// utils/crypto.js
// All cryptography for Data Chain lives here. Node's built-in `crypto`
// module is used throughout - no third-party crypto libraries, which keeps
// this defensible in a viva ("what library implements your encryption?"
// -> "Node's native crypto module, nothing homemade").

// Node.js built-in cryptography module — battle-tested, maintained by
// the Node.js core team, and based on OpenSSL (one of the most widely
// used crypto libraries in the world). Using a built-in module instead
// of a third-party package avoids supply-chain attacks (where a
// compromised npm package could steal encryption keys).
const crypto = require('crypto');

// ============================================================================
// PBKDF2 CONFIGURATION CONSTANTS
// ============================================================================
// These constants control how passwords are converted into encryption keys.
//
// PBKDF2_ITERATIONS (100,000):
//   How many times the hash function is run. More iterations = slower to
//   compute = harder for attackers to brute-force. 100,000 is NIST's
//   minimum recommendation. Each password guess takes 100,000× longer
//   than a single hash, making dictionary attacks impractically slow.
//
// PBKDF2_KEYLEN (32 bytes = 256 bits):
//   The output key length. 32 bytes = 256 bits, which matches the key
//   size needed for AES-256 encryption.
//
// PBKDF2_DIGEST ('sha256'):
//   The underlying hash algorithm used in each PBKDF2 iteration.
// ============================================================================
const PBKDF2_ITERATIONS = 100000;
const PBKDF2_KEYLEN = 32; // 256-bit key
const PBKDF2_DIGEST = 'sha256';

// ============================================================================
// generateRSAKeyPair — Creates a New Public/Private Key Pair
// ============================================================================
// PURPOSE:
//   Called once during user signup to generate a unique RSA key pair.
//   The PUBLIC key is stored on the server (safe to share — that's the
//   whole point of asymmetric crypto). The PRIVATE key is encrypted with
//   the user's password and downloaded as a .key file — it is NEVER
//   stored on the server. If the user loses this file, their encrypted
//   files become permanently unrecoverable.
//
// RSA-2048:
//   RSA with a 2048-bit key length. This is the current industry standard
//   minimum. The larger the key, the harder it is to crack, but also the
//   slower the encryption. 2048 bits is considered secure until at least
//   2030 by NIST.
//
// PEM FORMAT:
//   PEM (Privacy-Enhanced Mail) is a text-based format for cryptographic
//   keys, starting with "-----BEGIN PUBLIC KEY-----". It's the most
//   widely supported format and can be easily saved to a file.
//
// KEY ENCODING TYPES:
//   - SPKI (Subject Public Key Info): standard format for public keys
//   - PKCS#8: standard format for private keys (supports encryption)
// ============================================================================

/**
 * Generates a fresh RSA-2048 keypair.
 * Returns PEM strings for both keys - PEM is the standard text format
 * for keys, easy to store as a file and easy to read back later.
 */
function generateRSAKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,                                    // Key size in bits
    publicKeyEncoding: { type: 'spki', format: 'pem' },     // Standard public key format
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }    // Standard private key format
  });
  return { publicKey, privateKey };
}

// ============================================================================
// deriveKeyFromPassword — Converts a Password into an Encryption Key
// ============================================================================
// PURPOSE:
//   Passwords like "MyP@ssw0rd" are not suitable as encryption keys
//   directly — they're too short, too predictable, and not random enough.
//   PBKDF2 transforms a password into a proper 256-bit cryptographic key
//   by repeatedly hashing it with a random salt.
//
// THE SALT:
//   A salt is a random value mixed in with the password before hashing.
//   Even if two users choose the same password, different salts produce
//   different keys. This defeats "rainbow table" attacks (precomputed
//   hash lookups).
//
// WHY 100,000 ITERATIONS?
//   Each iteration adds computation time. For a legitimate user logging
//   in once, the extra ~100ms is unnoticeable. But for an attacker trying
//   billions of password guesses, each guess now takes 100,000× longer.
//   This is called "key stretching" — it stretches the time needed for
//   each brute-force attempt.
// ============================================================================

/**
 * Derives a 256-bit AES key from a password + salt using PBKDF2.
 * Same function is mirrored on the client (browser) side so the same
 * password always regenerates the same AES key from the same salt.
 */
function deriveKeyFromPassword(password, salt) {
  return crypto.pbkdf2Sync(password, salt, PBKDF2_ITERATIONS, PBKDF2_KEYLEN, PBKDF2_DIGEST);
}

// ============================================================================
// encryptPrivateKey — Protects the Private Key with the User's Password
// ============================================================================
// PURPOSE:
//   The user's RSA private key is extremely sensitive — anyone who has it
//   can decrypt all files encrypted for that user. So before handing it
//   to the user as a downloadable file, we encrypt it with a key derived
//   from their password.
//
// HOW IT WORKS:
//   1. Generate a random 16-byte salt for PBKDF2
//   2. Derive an AES-256 key from the user's password + salt
//   3. Generate a random 12-byte IV (Initialization Vector) for AES-GCM
//   4. Encrypt the private key text with AES-256-GCM
//   5. Return all the pieces needed for decryption (salt, IV, authTag,
//      ciphertext, algorithm info)
//
// WHAT IS AN IV (Initialization Vector)?
//   A random value used to ensure that encrypting the same data twice
//   produces different ciphertexts. Without an IV, identical inputs
//   would produce identical outputs, leaking information about the data.
//
// WHAT IS AN AUTH TAG (Authentication Tag)?
//   GCM mode produces a 16-byte authentication tag alongside the
//   ciphertext. When decrypting, the tag is checked to confirm that
//   the ciphertext hasn't been tampered with. If someone modifies even
//   one byte of the encrypted data, the auth tag check will fail,
//   alerting you to tampering. This is called "authenticated encryption."
//
// SERVER NEVER KEEPS A COPY:
//   The encrypted private key is returned in the signup response and
//   downloaded by the browser. The server does NOT store it. If the
//   user loses the file, the key is gone forever — that's the tradeoff
//   of a true client-side-only key model.
// ============================================================================

/**
 * Encrypts a user's freshly generated private key with a key derived from
 * their account password, so that ONLY someone who knows the password can
 * ever unlock it. The output is what gets handed to the browser as a
 * downloadable .key file. The server does not keep a copy.
 */
function encryptPrivateKey(privateKeyPem, password) {
  // Generate a random salt for PBKDF2 key derivation.
  const salt = crypto.randomBytes(16);

  // Derive a 256-bit AES key from the user's password + salt.
  const key = deriveKeyFromPassword(password, salt);

  // Generate a random 12-byte IV (Initialization Vector).
  // 12 bytes is the recommended IV size for GCM mode.
  const iv = crypto.randomBytes(12); // recommended IV size for GCM

  // Create an AES-256-GCM cipher and encrypt the private key.
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(privateKeyPem, 'utf8'), cipher.final()]);

  // Get the authentication tag — this will be used during decryption
  // to verify that the ciphertext hasn't been tampered with.
  const authTag = cipher.getAuthTag();

  // Return all components needed for decryption. Everything except the
  // password itself is included — the password stays in the user's head.
  return {
    salt: salt.toString('base64'),           // PBKDF2 salt (needed to re-derive the key)
    iv: iv.toString('base64'),               // AES-GCM IV (needed for decryption)
    authTag: authTag.toString('base64'),     // Authentication tag (tamper detection)
    ciphertext: ciphertext.toString('base64'), // The encrypted private key
    algorithm: 'aes-256-gcm',                // Which algorithm was used
    kdf: 'pbkdf2-sha256',                    // Which key derivation function was used
    kdfIterations: PBKDF2_ITERATIONS         // How many iterations (needed to re-derive)
  };
}

// ============================================================================
// hashBuffer — Creates a SHA-256 Fingerprint of File Contents
// ============================================================================
// PURPOSE:
//   Computes a unique 64-character hex string that represents a file's
//   contents. This hash is used in two critical ways:
//
//   1. INTEGRITY VERIFICATION:
//      After downloading a file, the recipient can re-hash the decrypted
//      content and compare it to the original hash. If they match, the
//      file hasn't been corrupted or tampered with.
//
//   2. BLOCKCHAIN LOGGING:
//      The file's hash (NOT the file itself) is recorded in the blockchain
//      ledger. This proves that a specific file was uploaded/sent/downloaded
//      without storing the actual file contents in the ledger.
//
// WHY HASH THE FILE AND NOT STORE IT?
//   Files can be huge (megabytes). Hashes are always 64 characters.
//   Storing hashes in the blockchain keeps the ledger compact while still
//   providing provable integrity.
// ============================================================================

/**
 * SHA-256 hash of a file buffer. Used two ways:
 *  1. Integrity check - re-hash on download and compare to the original.
 *  2. Blockchain payload - the hash (not the file) is what gets logged.
 */
function hashBuffer(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

// ============================================================================
// encryptFileEnvelope — Envelope Encryption for a Single Recipient
// ============================================================================
// PURPOSE:
//   Encrypts a file so that ONLY the intended recipient can decrypt it.
//   Uses "envelope encryption" — a standard pattern used by AWS, Google
//   Cloud, and virtually every major platform that handles encrypted data.
//
// WHY NOT JUST USE RSA?
//   RSA can only encrypt data smaller than its key size (for RSA-2048,
//   that's about 245 bytes). Most files are much larger than that.
//
// WHY NOT JUST USE AES?
//   AES can encrypt any size, but both the sender and recipient need the
//   SAME key. How do you securely share that key? You'd need... encryption.
//   It's a chicken-and-egg problem.
//
// ENVELOPE ENCRYPTION SOLVES BOTH PROBLEMS:
//   Step 1: Generate a random AES key (32 bytes = 256 bits)
//   Step 2: Encrypt the FILE with AES-256-GCM (fast, any size)
//   Step 3: Encrypt the small AES KEY with RSA using the recipient's
//           public key (only their private key can recover it)
//   Step 4: Store both the encrypted file AND the encrypted key together
//
// TO DECRYPT:
//   Step 1: Use your RSA private key to decrypt the AES key
//   Step 2: Use the recovered AES key to decrypt the file
//
// ANALOGY:
//   Imagine you want to send a locked safe (file) to someone. You:
//   1. Put the file in a safe and lock it with a random combination (AES key)
//   2. Write the combination on a note
//   3. Put the note in a small lockbox that only the recipient can open
//      (RSA encryption with their public key)
//   4. Send both the safe and the lockbox
//   The recipient opens the lockbox with their private key, reads the
//   combination, and opens the safe.
// ============================================================================

/**
 * Envelope encryption for a file:
 *  1. Generate a random one-time AES-256 key.
 *  2. Encrypt the file with it (AES-GCM - fast, works on any file size).
 *  3. Encrypt that small AES key with the recipient's RSA public key
 *     (RSA-OAEP - only their private key can recover it).
 * This is why RSA and AES are used together: RSA alone can't encrypt
 * anything larger than its key size, AES alone has no easy way to share
 * a secret key safely. Combined, you get the best of both.
 */
function encryptFileEnvelope(fileBuffer, recipientPublicKeyPem) {
  // Step 1: Generate a random 256-bit AES key. This key is used ONCE
  // for this specific file — a new random key is generated for every
  // encryption operation. This is called a "data encryption key" (DEK).
  const aesKey = crypto.randomBytes(32);

  // Generate a random 12-byte IV for AES-GCM.
  const iv = crypto.randomBytes(12);

  // Step 2: Encrypt the file with AES-256-GCM.
  // GCM (Galois/Counter Mode) provides both encryption AND authentication
  // — it encrypts the data AND produces a tag that detects tampering.
  const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
  const encryptedFile = Buffer.concat([cipher.update(fileBuffer), cipher.final()]);
  const authTag = cipher.getAuthTag();

  // Step 3: Encrypt the AES key with the recipient's RSA public key.
  // RSA-OAEP (Optimal Asymmetric Encryption Padding) is the recommended
  // padding scheme — it's more secure than the older PKCS#1 v1.5 padding
  // because it's resistant to certain cryptographic attacks.
  const encryptedKey = crypto.publicEncrypt(
    {
      key: recipientPublicKeyPem,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,  // Secure padding scheme
      oaepHash: 'sha256'                                   // Hash used in OAEP padding
    },
    aesKey  // The small AES key being wrapped (only 32 bytes)
  );

  // Return all components needed for decryption:
  return {
    encryptedFile,                              // The encrypted file data
    iv: iv.toString('base64'),                  // IV needed for AES-GCM decryption
    authTag: authTag.toString('base64'),        // Auth tag for tamper detection
    encryptedKey: encryptedKey.toString('base64') // RSA-wrapped AES key
  };
}

// ============================================================================
// encryptFileForRecipients — Multi-Recipient Envelope Encryption (Groups)
// ============================================================================
// PURPOSE:
//   Same concept as encryptFileEnvelope, but for GROUP file sharing where
//   multiple users need to decrypt the same file.
//
// HOW IT WORKS:
//   The file is encrypted ONCE with a single random AES key (efficient —
//   no need to encrypt a large file multiple times). Then that small AES
//   key is separately RSA-wrapped for EACH group member's public key.
//
//   Result: each member gets their own copy of the encrypted AES key that
//   only THEIR private key can unwrap. But they all decrypt the same
//   encrypted file.
//
// WHY NOT ENCRYPT THE FILE SEPARATELY FOR EACH MEMBER?
//   If a file is 10MB and the group has 5 members, encrypting separately
//   would require 50MB of storage. With envelope encryption, we store
//   10MB of encrypted file + 5 tiny encrypted keys (< 1KB total).
//   This is dramatically more efficient.
//
// RETURNS:
//   {
//     encryptedFile:  the encrypted file data (same for everyone),
//     iv:             the AES-GCM initialization vector,
//     authTag:        the authentication tag for tamper detection,
//     wrappedKeys:    array of { email, encryptedKey } — one per member
//   }
// ============================================================================

/**
 * Same idea as encryptFileEnvelope, but wraps the ONE random AES key
 * separately for MULTIPLE recipients instead of just one. This is what
 * lets every member of a group decrypt the same file with their own
 * private key - the file itself is only encrypted once (efficient),
 * only the small AES key gets RSA-wrapped per person.
 */
function encryptFileForRecipients(fileBuffer, recipients) {
  // Generate a single random AES key — shared across all recipients
  // (but each one gets their own RSA-encrypted copy of it).
  const aesKey = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);

  // Encrypt the file ONCE with AES-256-GCM.
  const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
  const encryptedFile = Buffer.concat([cipher.update(fileBuffer), cipher.final()]);
  const authTag = cipher.getAuthTag();

  // Wrap the AES key separately for each recipient using their individual
  // RSA public key. Each member gets a personalized "envelope" that only
  // their private key can open.
  const wrappedKeys = recipients.map(({ email, publicKey }) => ({
    email,
    encryptedKey: crypto.publicEncrypt(
      { key: publicKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
      aesKey
    ).toString('base64')
  }));

  return {
    encryptedFile,                         // Single encrypted copy of the file
    iv: iv.toString('base64'),             // AES-GCM IV
    authTag: authTag.toString('base64'),   // Authentication tag
    wrappedKeys                            // Array of { email, encryptedKey } per member
  };
}

// Export all cryptographic functions for use by other modules:
//   - generateRSAKeyPair     → routes/auth.js (signup)
//   - deriveKeyFromPassword  → internal use (encryptPrivateKey)
//   - encryptPrivateKey      → routes/auth.js (signup, downloadable .key file)
//   - hashBuffer             → routes/files.js, routes/groups.js (file fingerprinting)
//   - encryptFileEnvelope    → routes/files.js (personal & direct file encryption)
//   - encryptFileForRecipients → routes/files.js, routes/groups.js (group encryption)
//   - PBKDF2_ITERATIONS      → exported so client-side code can use the same value
module.exports = {
  generateRSAKeyPair,
  deriveKeyFromPassword,
  encryptPrivateKey,
  hashBuffer,
  encryptFileEnvelope,
  encryptFileForRecipients,
  PBKDF2_ITERATIONS
};
