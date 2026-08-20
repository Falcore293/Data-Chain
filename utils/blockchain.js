// ============================================================================
// utils/blockchain.js — Hash-Chained Audit Ledger (Core Security Module)
// ============================================================================
//
// WHAT IS THIS FILE?
// ------------------
// This is the HEART of Data Chain's tamper-detection system. It implements
// a hash-chained ledger — a series of records ("blocks") where each block
// contains the digital fingerprint ("hash") of the block before it,
// creating an unbreakable chain.
//
// IMPORTANT DISTINCTION:
// ----------------------
// This is NOT a distributed blockchain like Bitcoin or Ethereum. Those
// systems run on thousands of computers and use "consensus" algorithms
// to agree on the state of the chain. This is a SINGLE-SERVER ledger.
// But it still provides a real, valuable security property:
//
//   → If anyone edits an old record directly in the database (bypassing
//     the application), every hash after that point stops matching, and
//     the tampering becomes DETECTABLE.
//
// WHAT IS A HASH?
// ---------------
// A hash is a fixed-length digital fingerprint of some data. Think of it
// like a unique barcode that represents the contents of a document:
//   - The SAME input always produces the SAME hash
//   - Even a TINY change in input produces a COMPLETELY different hash
//   - You CANNOT reverse-engineer the original data from the hash
//   - Two different inputs will (practically) NEVER produce the same hash
//
// This project uses SHA-256 (Secure Hash Algorithm, 256-bit), which
// produces a 64-character hexadecimal string (e.g., "a3f2b8c1d4e5...").
//
// HOW THE CHAIN WORKS:
// --------------------
//   Block 0 (genesis): previousHash = "000...000" (64 zeros)
//                       blockHash = SHA-256(all block 0 data + "000...000")
//
//   Block 1:           previousHash = block 0's blockHash
//                       blockHash = SHA-256(all block 1 data + block 0's hash)
//
//   Block 2:           previousHash = block 1's blockHash
//                       blockHash = SHA-256(all block 2 data + block 1's hash)
//
// If someone changes Block 1's data, its blockHash changes. But Block 2
// still stores the OLD hash in its previousHash field → mismatch detected!
// And Block 2's own hash also changes → Block 3 mismatches → and so on.
// The corruption cascades through the entire rest of the chain.
// ============================================================================

// utils/blockchain.js
// A hash-chained audit log, honestly framed: this is NOT a distributed
// blockchain (no consensus, no multiple nodes) - it's a single-server
// ledger where each entry embeds the previous entry's hash. That still
// gives a real security property worth having: if anyone edits an old
// row directly in the database, every block hash after it stops matching,
// so tampering becomes detectable.

// Node.js built-in cryptography module — provides SHA-256 hashing and
// other cryptographic functions. Using the built-in module (not a
// third-party library) is a deliberate security choice: it's maintained
// by the Node.js team, well-audited, and doesn't introduce supply-chain
// risk from external dependencies.
const crypto = require('crypto');

// Database connection — needed to read/write blocks from the transactions table.
const { getDB } = require('../db/database');

// ============================================================================
// GENESIS HASH
// ============================================================================
// The very first block in the chain (Block 0, the "genesis block") has no
// previous block to reference. So by convention, we use a string of 64
// zeros as its "previousHash". This is an arbitrary but consistent starting
// point — like saying "page 0" in a book that starts at page 1.
//
// Why 64 zeros? Because SHA-256 produces a 64-character hex string, so
// the genesis hash has the same length as a real hash, keeping the format
// consistent throughout the chain.
// ============================================================================
const GENESIS_HASH = '0'.repeat(64);

// ============================================================================
// computeBlockHash — Creates a Unique Digital Fingerprint for a Block
// ============================================================================
// PURPOSE:
//   Takes all the data fields of a block and combines them into a single
//   string, then runs SHA-256 on that string to produce a unique hash.
//
// WHY INCLUDE ALL FIELDS?
//   If we only hashed SOME fields, an attacker could change the un-hashed
//   fields without detection. By including EVERY field (index, action,
//   sender, receiver, fileHash, timestamp, AND the previous block's hash),
//   changing ANY piece of data will produce a different hash.
//
// THE PIPE (|) SEPARATOR:
//   Fields are joined with | characters to prevent "collision" attacks
//   where different field combinations could produce the same concatenated
//   string. For example, without separators:
//     sender="ab" + receiver="cd" = "abcd"
//     sender="abc" + receiver="d" = "abcd"  ← same string, different data!
//   With separators: "ab|cd" vs "abc|d" — clearly different.
//
// RETURNS:
//   A 64-character hexadecimal string (the SHA-256 hash).
// ============================================================================
function computeBlockHash({ blockIndex, action, sender, receiver, fileHash, timestamp, previousHash }) {
  // Concatenate all block fields into a single string with | separators.
  // The (receiver || '') handles the case where receiver is null (e.g.,
  // for personal uploads that aren't sent to anyone).
  const payload = `${blockIndex}|${action}|${sender}|${receiver || ''}|${fileHash}|${timestamp}|${previousHash}`;

  // Create a SHA-256 hash of the payload and return it as a hex string.
  // .createHash('sha256') → select the SHA-256 algorithm
  // .update(payload)      → feed the data into the hash function
  // .digest('hex')        → output the result as hexadecimal (0-9, a-f)
  return crypto.createHash('sha256').update(payload).digest('hex');
}

// ============================================================================
// addBlock — Appends a New Block to the Ledger
// ============================================================================
// PURPOSE:
//   Called every time a significant file action occurs (upload, send,
//   download, new version, access update, group operations). Creates a
//   new block that chains onto the end of the existing ledger.
//
// STEPS:
//   1. Read the last block's hash from the database
//   2. Compute the new block's index (last + 1) and previousHash
//   3. Record the current timestamp
//   4. Compute this block's own hash from all its data
//   5. Insert the new block into the database
//
// WHY IS THE PREVIOUS HASH IMPORTANT?
//   The previousHash field is what creates the "chain". Each block is
//   linked to the one before it. If Block 5 stores Block 4's hash, and
//   someone later changes Block 4, Block 5's previousHash will no longer
//   match Block 4's recalculated hash → tampering detected.
//
// RETURNS:
//   { blockIndex, previousHash, blockHash, timestamp } — metadata about
//   the newly created block, useful for the API response.
// ============================================================================

/**
 * Appends a new block to the ledger for a file action (upload / send / download).
 * Reads the last block's hash, chains onto it, and inserts the new row.
 */
async function addBlock({ action, sender, receiver, fileHash }) {
  // Open a database connection.
  const db = await getDB();

  // Step 1: Get the most recent block from the database.
  // We need its blockIndex (to compute the next index) and its blockHash
  // (to use as the new block's previousHash).
  const lastBlock = await db.get(
    'SELECT blockIndex, blockHash FROM transactions ORDER BY blockIndex DESC LIMIT 1'
  );

  // Step 2: If there are no blocks yet, this is the genesis block (index 0).
  // Otherwise, increment the last block's index by 1.
  const blockIndex = lastBlock ? lastBlock.blockIndex + 1 : 0;

  // Step 3: Link to the previous block's hash. If this is the first block,
  // use the GENESIS_HASH (64 zeros) as the starting point.
  const previousHash = lastBlock ? lastBlock.blockHash : GENESIS_HASH;

  // Step 4: Record exactly when this block was created (ISO 8601 format).
  // This timestamp becomes part of the hash, so it can't be changed later
  // without breaking the chain.
  const timestamp = new Date().toISOString();

  // Step 5: Compute this block's unique hash from ALL of its data fields.
  // This hash is the block's "fingerprint" — if any field changes, the
  // hash will be completely different.
  const blockHash = computeBlockHash({ blockIndex, action, sender, receiver, fileHash, timestamp, previousHash });

  // Step 6: Insert the new block into the database's transactions table.
  // The ? placeholders prevent SQL injection — a common attack where
  // malicious input is crafted to manipulate database queries.
  await db.run(
    `INSERT INTO transactions (blockIndex, action, sender, receiver, fileHash, timestamp, previousHash, blockHash)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    [blockIndex, action, sender, receiver || null, fileHash, timestamp, previousHash, blockHash]
  );

  // Return the new block's metadata so the API can include it in the response.
  return { blockIndex, previousHash, blockHash, timestamp };
}

// ============================================================================
// validateChain — Integrity Verification (Tamper Detection)
// ============================================================================
// PURPOSE:
//   This is the function that PROVES whether the ledger has been tampered
//   with. It reads every block from first to last and performs two checks
//   on each one:
//
//   CHECK 1 — Chain Link Integrity:
//     Does this block's "previousHash" field match the hash of the block
//     before it? If not, someone may have inserted, deleted, or reordered
//     blocks.
//
//   CHECK 2 — Block Content Integrity:
//     If we recompute this block's hash from its current data, does it
//     match the stored blockHash? If not, someone changed the block's
//     content (e.g., modified the sender, receiver, or timestamp).
//
// IF BOTH CHECKS PASS FOR ALL BLOCKS:
//   → { valid: true, blockCount: N }
//   The entire ledger is intact. No records have been tampered with.
//
// IF EITHER CHECK FAILS:
//   → { valid: false, brokenAt: X, reason: '...' }
//   The chain is broken at block X. This tells you exactly where the
//   tampering occurred.
//
// ANALOGY:
//   Imagine a chain of sealed envelopes. Each envelope contains a letter
//   AND a photograph of the previous envelope's seal. To verify the chain:
//     1. Open envelope #1. Check its seal against envelope #2's photo.
//     2. Open envelope #2. Check its seal against envelope #3's photo.
//     3. Continue until the end.
//   If any photo doesn't match the actual seal, someone opened and
//   resealed an envelope — tampering detected!
// ============================================================================

/**
 * Walks the entire chain and recomputes every hash to confirm nothing
 * was altered out-of-band. Powers the "blockchain viewer / validate chain"
 * feature.
 */
async function validateChain() {
  // Open a database connection and fetch ALL blocks, sorted by index
  // in ASCENDING order (oldest first). We need to walk the chain from
  // the beginning because each block depends on the one before it.
  const db = await getDB();
  const blocks = await db.all('SELECT * FROM transactions ORDER BY blockIndex ASC');

  // Start with the genesis hash — the expected "previousHash" of Block 0.
  let expectedPrevious = GENESIS_HASH;

  // Walk through every block in order.
  for (const block of blocks) {

    // CHECK 1: Does this block's previousHash match what we expect?
    // (i.e., the hash of the block before it, or GENESIS_HASH for Block 0)
    // If not, someone may have tampered with the previous block, inserted
    // a block, or deleted one.
    if (block.previousHash !== expectedPrevious) {
      return { valid: false, brokenAt: block.blockIndex, reason: 'previousHash mismatch' };
    }

    // CHECK 2: Recompute this block's hash from its current data fields.
    // If the recomputed hash doesn't match the stored blockHash, it means
    // someone changed the block's data after it was originally created.
    const recomputed = computeBlockHash(block);
    if (recomputed !== block.blockHash) {
      return { valid: false, brokenAt: block.blockIndex, reason: 'blockHash does not match block contents' };
    }

    // This block is valid. Its hash becomes the expected previousHash
    // for the NEXT block in the chain.
    expectedPrevious = block.blockHash;
  }

  // If we made it through every block without finding a mismatch,
  // the entire chain is intact and untampered.
  return { valid: true, blockCount: blocks.length };
}

// Export the functions so they can be used by other modules:
//   addBlock     → called by routes/files.js, routes/groups.js
//   validateChain → called by routes/blockchain.js
//   GENESIS_HASH → the starting hash constant
module.exports = { addBlock, validateChain, GENESIS_HASH };
