// ============================================================================
// routes/blockchain.js — Blockchain Ledger API Routes
// ============================================================================
//
// WHAT IS THIS FILE?
// ------------------
// This file defines the API endpoints (URLs) that the front-end calls when
// a user wants to:
//   1. View the blockchain ledger  (GET /api/blockchain)
//   2. Validate the blockchain     (GET /api/blockchain/validate)
//
// Think of a "route" like a reception desk: when a request arrives at a
// specific URL, the code here decides what to do with it and what to send
// back.
//
// WHY BLOCKCHAIN?
// ---------------
// Every time someone uploads, sends, or downloads a file, the system
// creates a new "block" (a record) and chains it to the previous one
// using a cryptographic hash — a digital fingerprint. If anyone secretly
// edits an old record (e.g. directly modifying the database file), the
// fingerprint of that record will no longer match, breaking the chain
// from that point onward. This is called **tamper detection** — the
// system can't prevent edits, but it can reliably *detect* them.
//
// SECURITY CONCEPTS USED IN THIS FILE:
// -------------------------------------
//  • Authentication (authn) — verifying *who* is making the request
//    (handled by the requireAuth middleware, which checks the JWT token).
//  • Authorization (authz) — verifying *what* the authenticated user is
//    allowed to do (e.g. only admins can view the full ledger).
//  • Principle of Least Privilege — regular users only see the blocks
//    that concern them, not the entire ledger.
//  • Integrity Verification — the /validate endpoint recalculates every
//    hash to confirm no record was tampered with.
// ============================================================================

// --- IMPORTS (loading the tools this file needs) ---

// Express is the web framework that handles incoming HTTP requests and
// sends back responses (like a postal service for web traffic).
const express = require('express');

// getDB gives us a connection to the SQLite database where all blockchain
// blocks (transaction records) are stored.
const { getDB } = require('../db/database');

// requireAuth is a "middleware" — a security checkpoint that runs BEFORE
// our route code. It checks the JWT (JSON Web Token) in the request
// header to confirm the user is logged in. If the token is missing or
// invalid, the request is rejected with a 401 Unauthorized error and
// our route code never executes. This prevents unauthenticated
// (anonymous) users from accessing the blockchain data.
const { requireAuth } = require('../middleware/auth');

// validateChain is a utility function that walks through every block in
// the database, recalculates each block's hash from scratch, and checks
// that each block correctly references the previous block's hash. If
// any block has been tampered with, the recalculated hash won't match
// the stored hash, and the function reports exactly where the chain
// broke. (See utils/blockchain.js for the full implementation.)
const { validateChain } = require('../utils/blockchain');

// Create a new Express "router" — a mini-application that groups related
// routes together. This router is later mounted at /api/blockchain in
// the main server file (server.js).
const router = express.Router();

// ============================================================================
// ROUTE 1: GET /api/blockchain?scope=mine|all
// ============================================================================
//
// PURPOSE:
//   Returns blockchain blocks (transaction records) to the front-end so
//   the user can see a history of file actions. The "scope" query
//   parameter controls how much of the ledger the user sees:
//
//     • scope=mine (default) — shows only blocks that involve the
//       logged-in user: files they uploaded, sent, received, or
//       downloaded, plus activity in groups they belong to.
//
//     • scope=all — shows the ENTIRE ledger across all users. This is
//       restricted to admin accounts only, because exposing every user's
//       file activity to everyone would violate the privacy principle.
//       Admins need this for auditing and for demonstrating the tamper-
//       evidence property of the full chain.
//
// IMPORTANT SECURITY NOTE:
//   The underlying blockchain itself is always complete — every user's
//   actions are recorded in every case. The scope filter is purely a
//   *display-level* filter. Nothing is deleted or hidden from the
//   actual chain. This preserves the integrity of the hash chain
//   while still respecting user privacy in the UI.
//
// HOW THE CHAIN WORKS (simplified):
//   Block 0 (genesis) ← Block 1 ← Block 2 ← Block 3 ← ...
//   Each block contains:
//     - blockIndex:    its position in the chain (0, 1, 2, ...)
//     - action:        what happened (upload / send / download)
//     - sender:        who performed the action
//     - receiver:      who received the file (or a group tag)
//     - fileHash:      SHA-256 fingerprint of the file contents
//     - timestamp:     when it happened
//     - previousHash:  the hash of the block before it (this is the
//                      "chain" — it links blocks together)
//     - blockHash:     this block's own hash, computed from ALL the
//                      fields above, making it tamper-evident
// ============================================================================

// GET /api/blockchain?scope=mine|all
// Defaults to "mine" - only blocks the logged-in user is actually
// party to (they uploaded/sent/received/downloaded, or it happened in
// a group they're a member of). The full ledger is still there
// underneath (nothing is deleted or hidden from the chain itself,
// addBlock() still records everything, everyone's actions included) -
// this is purely a display filter for "what does this concern me"
// convenience. scope=all shows the whole ledger, useful for a viva demo
// of the tamper-evidence property across the whole system.
router.get('/', requireAuth, async (req, res) => {

  // Open a connection to the database so we can read blocks from it.
  const db = await getDB();

  // Extract the logged-in user's email from the decoded JWT token.
  // The requireAuth middleware already verified the token and attached
  // the user's identity to req.user, so we can trust this value.
  const email = req.user.email;

  // Check whether the user is asking for scope=all (the full ledger).
  const requestedAll = req.query.scope === 'all';

  // --- AUTHORIZATION CHECK (Role-Based Access Control / RBAC) ---
  // If the user wants the full ledger but is NOT an admin, deny the
  // request with HTTP 403 Forbidden. This enforces the principle of
  // least privilege: regular users should only see their own data.
  // A 403 means "I know who you are, but you don't have permission."
  // (Compare with 401, which means "I don't know who you are at all.")
  if (requestedAll && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Only admins can view the full ledger' });
  }
  const scope = requestedAll ? 'all' : 'mine';

  // Fetch ALL blocks from the database, sorted by blockIndex in
  // descending order (newest first) so the most recent activity
  // appears at the top of the ledger view.
  const allBlocks = await db.all('SELECT * FROM transactions ORDER BY blockIndex DESC');

  // If the admin requested the full ledger, return everything
  // immediately — no filtering needed.
  if (scope === 'all') {
    return res.json({ blocks: allBlocks, count: allBlocks.length, scope });
  }

  // --- FILTERING FOR "MY" BLOCKS ---
  // For regular users (scope=mine), we need to filter the ledger down
  // to only the blocks that are relevant to them.

  // Step 1: Look up which groups this user belongs to. Groups allow
  // multiple users to share files; if a file was sent to a group the
  // user is in, they should see that block too.
  const myGroups = await db.all('SELECT groupId FROM group_members WHERE memberEmail = ?', [email]);

  // Step 2: Build a Set of group tags (e.g. "group:abc123") for fast
  // lookup. A Set lets us check membership in O(1) time — much faster
  // than scanning an array — which matters if the ledger is large.
  const groupTags = new Set(myGroups.map((g) => `group:${g.groupId}`));

  // Step 3: Filter the blocks. A block is "mine" if:
  //   • I am the sender  (I uploaded or sent the file), OR
  //   • I am the receiver (someone sent the file to me), OR
  //   • The receiver is a group I belong to (group file sharing)
  const blocks = allBlocks.filter(
    (b) => b.sender === email || b.receiver === email || groupTags.has(b.receiver)
  );

  // Return the filtered blocks along with the count and scope label
  // so the front-end knows what it's displaying.
  res.json({ blocks, count: blocks.length, scope });
});

// ============================================================================
// ROUTE 2: GET /api/blockchain/validate
// ============================================================================
//
// PURPOSE:
//   This is the **integrity verification** endpoint — the core security
//   feature of the blockchain. When called, it walks through every single
//   block in the chain from the very first one (the "genesis block") to
//   the latest, and for each block it:
//
//     1. Checks that the block's "previousHash" field matches the hash
//        of the block before it (verifying the chain links are intact).
//
//     2. Recalculates the block's hash from its data fields (index,
//        action, sender, receiver, fileHash, timestamp, previousHash)
//        and compares it to the stored blockHash.
//
//   If BOTH checks pass for every block, the chain is valid — no records
//   have been tampered with. If either check fails, the response tells
//   you exactly which block was corrupted and why.
//
// WHY THIS MATTERS:
//   Imagine someone gains access to the database file and changes a
//   record — for example, changing the sender of a file transfer to
//   frame someone else. Because the block's hash was computed from ALL
//   of its data, changing any field causes the recalculated hash to
//   differ from the stored hash. Additionally, since the NEXT block
//   references this block's hash, the entire chain after the tampered
//   block also becomes invalid. This cascading effect makes even a
//   single-byte change detectable — this is called **tamper evidence**.
//
// ANALOGY:
//   Think of it like a stack of sealed envelopes. Each envelope contains
//   a letter AND a photo of the previous envelope's seal. If someone
//   opens an envelope and changes the letter, they'd need a new seal —
//   but then the next envelope's photo wouldn't match the new seal.
//   You'd have to re-seal every envelope after it, which is impossible
//   without the original sealing tool (the hash function's inputs).
// ============================================================================

// GET /api/blockchain/validate
// Walks the whole chain and recomputes every hash to confirm nothing
// was altered outside of normal application flow (e.g. someone editing
// the SQLite file directly).
router.get('/validate', requireAuth, async (req, res) => {
  // Call the validateChain() utility which does the heavy lifting:
  // it reads every block, recomputes hashes, and returns either
  // { valid: true, blockCount: N } or
  // { valid: false, brokenAt: X, reason: '...' }
  const result = await validateChain();

  // Send the validation result back to the front-end. The UI can
  // then display a green "chain is intact" or red "chain broken at
  // block X" indicator to the user.
  res.json(result);
});

// Export the router so it can be mounted in server.js at /api/blockchain.
module.exports = router;
