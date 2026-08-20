// ============================================================================
// routes/groups.js — Secure Group Folders & Multi-Recipient Encrypted Sharing
// ============================================================================
//
// WHAT IS THIS FILE?
// ------------------
// This file implements group collaboration features:
//   1. Create Group Folder (`POST /api/groups`)
//   2. List My Groups & Members (`GET /api/groups`, `GET /:id/members`)
//   3. Add Group Member (`POST /:id/members`) — Owner-only authorization
//   4. Share File with Group (`POST /:id/upload`) — Multi-recipient envelope encryption
//
// KEY SECURITY CONCEPTS & PATTERNS:
// ----------------------------------
//  • Multi-Recipient Envelope Encryption:
//    When sharing a file to a group, the file is encrypted ONCE using a single,
//    random AES-256 key. That AES key is then individually wrapped (RSA-encrypted)
//    for every current group member using their respective public RSA keys.
//
//  • Owner Authorization Control:
//    Only the group owner can invite new members. Adding members expands access
//    to future group files, so it is strictly guarded (`group.ownerEmail !== requester`).
//
//  • Blockchain Audit Logging (`addBlock`):
//    Group creation and group file uploads append immutable audit records to
//    the blockchain transaction ledger.
// ============================================================================

// routes/groups.js
const express = require('express');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const { getDB } = require('../db/database');
const { requireAuth, requireNotSuspended } = require('../middleware/auth');
const { hashBuffer, encryptFileForRecipients } = require('../utils/crypto');
const { addBlock } = require('../utils/blockchain');
const { computeExpiry } = require('../utils/expiry');

const router = express.Router();
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 50 * 1024 * 1024 } });

const UPLOAD_DIR = path.join(__dirname, '..', 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

/**
 * Checks if a specific user email is a member of the target group.
 */
async function isMember(db, groupId, email) {
  const row = await db.get('SELECT 1 FROM group_members WHERE groupId = ? AND memberEmail = ?', [groupId, email]);
  return !!row;
}

/**
 * Retrieves email address and RSA Public Key PEM for all active members of a group.
 */
async function getMembersWithKeys(db, groupId) {
  return db.all(
    `SELECT gm.memberEmail as email, pk.publicKeyPem as publicKey
     FROM group_members gm
     JOIN public_keys pk ON pk.email = gm.memberEmail
     WHERE gm.groupId = ?`,
    [groupId]
  );
}

// ============================================================================
// ROUTE: POST /api/groups (Create Group)
// ============================================================================
// Creates a new shared group folder. Creator becomes the group owner and
// initial member. Logs creation event to blockchain.
// ============================================================================

// POST /api/groups   { name }
router.post('/', requireAuth, async (req, res) => {
  try {
    const { name } = req.body;
    if (!name || !name.trim()) return res.status(400).json({ error: 'Group name is required' });

    const db = await getDB();
    const ownerEmail = req.user.email;

    const result = await db.run('INSERT INTO groups (name, ownerEmail) VALUES (?, ?)', [name.trim(), ownerEmail]);
    await db.run(
      'INSERT INTO group_members (groupId, memberEmail, addedBy) VALUES (?, ?, ?)',
      [result.lastID, ownerEmail, ownerEmail]
    );

    // Blockchain logging
    await addBlock({ action: 'group-created', sender: ownerEmail, receiver: null, fileHash: `group:${result.lastID}` });

    res.status(201).json({ groupId: result.lastID, name: name.trim() });
  } catch (err) {
    console.error('Create group error:', err);
    res.status(500).json({ error: 'Failed to create group' });
  }
});

// GET /api/groups (List groups requester is a member of)
router.get('/', requireAuth, async (req, res) => {
  const db = await getDB();
  const email = req.user.email;

  const groups = await db.all(
    `SELECT g.id, g.name, g.ownerEmail, g.createdAt,
            (SELECT COUNT(*) FROM group_members WHERE groupId = g.id) as memberCount
     FROM groups g
     JOIN group_members gm ON gm.groupId = g.id
     WHERE gm.memberEmail = ?
     ORDER BY g.createdAt DESC`,
    [email]
  );

  res.json({ groups: groups.map((g) => ({ ...g, isOwner: g.ownerEmail === email })) });
});

// GET /api/groups/:id/members (List group members - requires membership)
router.get('/:id/members', requireAuth, async (req, res) => {
  const db = await getDB();
  const email = req.user.email;

  if (!(await isMember(db, req.params.id, email))) {
    return res.status(403).json({ error: 'You are not a member of this group' });
  }

  const members = await db.all(
    'SELECT memberEmail, addedBy, joinedAt FROM group_members WHERE groupId = ? ORDER BY joinedAt ASC',
    [req.params.id]
  );
  res.json({ members });
});

// ============================================================================
// ROUTE: POST /api/groups/:id/members (Add Member - Owner Only)
// ============================================================================
// SECURITY CONTROL:
// Only the group owner can add new members. Adding members allows them to
// decrypt future group files, so authorization is strictly enforced.
// ============================================================================

// POST /api/groups/:id/members   { email }
router.post('/:id/members', requireAuth, async (req, res) => {
  try {
    const db = await getDB();
    const requester = req.user.email;
    const group = await db.get('SELECT * FROM groups WHERE id = ?', [req.params.id]);

    if (!group) return res.status(404).json({ error: 'Group not found' });
    
    // Authorization Check: Owner Only
    if (group.ownerEmail !== requester) return res.status(403).json({ error: 'Only the group owner can add members' });

    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email is required' });

    const targetUser = await db.get('SELECT email FROM users WHERE email = ?', [email]);
    if (!targetUser) return res.status(404).json({ error: 'No Data Chain account found for that email' });

    const targetKey = await db.get('SELECT email FROM public_keys WHERE email = ?', [email]);
    if (!targetKey) return res.status(400).json({ error: 'That user has no public key on record' });

    const already = await isMember(db, req.params.id, email);
    if (already) return res.status(409).json({ error: 'That user is already a member' });

    await db.run(
      'INSERT INTO group_members (groupId, memberEmail, addedBy) VALUES (?, ?, ?)',
      [req.params.id, email, requester]
    );

    res.status(201).json({ message: `${email} added to ${group.name}` });
  } catch (err) {
    console.error('Add member error:', err);
    res.status(500).json({ error: 'Failed to add member' });
  }
});

// ============================================================================
// ROUTE: POST /api/groups/:id/upload (Upload & Share File into Group)
// ============================================================================
// ENCRYPTION WORKFLOW:
//   1. Reads public RSA keys for ALL active group members.
//   2. Encrypts file ONCE using a fresh, random AES-256 key (`encryptFileForRecipients`).
//   3. Wraps the AES key separately for EACH member's RSA public key.
//   4. Writes encrypted file (.enc) to disk.
//   5. Stores wrapped key records in `version_keys` table.
//   6. Appends immutable block to blockchain & notifies members in real time.
// ============================================================================

// POST /api/groups/:id/upload
router.post('/:id/upload', requireAuth, requireNotSuspended, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file provided' });

    const db = await getDB();
    const email = req.user.email;
    const groupId = req.params.id;

    const group = await db.get('SELECT * FROM groups WHERE id = ?', [groupId]);
    if (!group) return res.status(404).json({ error: 'Group not found' });
    if (!(await isMember(db, groupId, email))) {
      return res.status(403).json({ error: 'You are not a member of this group' });
    }

    const members = await getMembersWithKeys(db, groupId);
    if (members.length === 0) {
      return res.status(400).json({ error: 'No group members have a public key on record' });
    }

    let expiresAt;
    try {
      ({ expiresAt } = computeExpiry(req.body.expiryType || 'none', req.body.customHours));
    } catch (e) {
      return res.status(400).json({ error: e.message });
    }

    const fileHash = hashBuffer(req.file.buffer); // SHA-256 fingerprint
    const { encryptedFile, iv, authTag, wrappedKeys } = encryptFileForRecipients(req.file.buffer, members);

    const storedName = `${crypto.randomUUID()}.enc`;
    fs.writeFileSync(path.join(UPLOAD_DIR, storedName), encryptedFile);

    const fileResult = await db.run(
      `INSERT INTO files (originalName, ownerEmail, receiverEmail, groupId, expiryType, expiresAt)
       VALUES (?, ?, NULL, ?, ?, ?)`,
      [req.file.originalname, email, groupId, req.body.expiryType || 'none', expiresAt]
    );
    const fileId = fileResult.lastID;

    const versionResult = await db.run(
      `INSERT INTO file_versions (fileId, versionNumber, storedName, fileHash, fileSize, iv, authTag, encryptedKey, uploadedBy)
       VALUES (?, 1, ?, ?, ?, ?, ?, NULL, ?)`,
      [fileId, storedName, fileHash, req.file.size, iv, authTag, email]
    );
    const versionId = versionResult.lastID;

    // Save individual wrapped RSA-AES keys for each group member
    for (const { email: memberEmail, encryptedKey } of wrappedKeys) {
      await db.run(
        'INSERT INTO version_keys (versionId, recipientEmail, encryptedKey) VALUES (?, ?, ?)',
        [versionId, memberEmail, encryptedKey]
      );
    }

    // Append to blockchain ledger
    const block = await addBlock({ action: 'group-upload', sender: email, receiver: `group:${groupId}`, fileHash });

    // Socket.IO real-time notification
    const io = req.app.get('io');
    for (const m of members) {
      if (m.email !== email) {
        io.to(m.email).emit('file-received', {
          fileId, from: email, originalName: req.file.originalname, groupName: group.name
        });
      }
    }

    io.to('admin-room').emit('file-traffic', {
      action: 'group-upload', email, groupName: group.name, fileName: req.file.originalname, size: req.file.size, timestamp: new Date().toISOString()
    });

    res.status(201).json({ message: `Shared to ${group.name}`, fileId, fileHash, block });
  } catch (err) {
    console.error('Group upload error:', err);
    res.status(500).json({ error: 'Failed to share file to group' });
  }
});

module.exports = router;

