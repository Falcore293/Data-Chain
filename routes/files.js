// ============================================================================
// routes/files.js — Secure File Operations & Envelope Encryption API Routes
// ============================================================================
//
// WHAT IS THIS FILE?
// ------------------
// This file handles secure file storage, transmission, versioning, and access:
//   1. File Upload (`POST /upload`) — Personal encrypted storage
//   2. Direct File Transfer (`POST /send`) — Encrypted 1:1 file sharing
//   3. File Versioning (`POST /:id/version`) — Immutable version history
//   4. Secure Downloading (`GET /:id/download`) — Key delivery & decryption payload
//   5. Time-Based Access Control Update (`PATCH /:id/access`)
//
// CORE SECURITY CONTROLS & ARCHITECTURE:
// ---------------------------------------
//  • Envelope Encryption:
//    Files are encrypted on the server using a fresh AES-256-GCM key per version.
//    That AES key is wrapped with the recipient's RSA-2048 Public Key.
//
//  • Granular Authorization (`canAccessFile`):
//    Strict access checks verify if the requester is the owner, direct receiver,
//    or an active group member. Unauthorized access attempts yield 403 Forbidden
//    and are recorded in `access_logs`.
//
//  • Instant Account Suspension (`requireNotSuspended`):
//    All upload/send/download routes enforce real-time DB suspension checks.
//
//  • Audit Trail & Blockchain Logging (`addBlock`):
//    Every file action (upload, send, download, new version, access change) appends
//    an immutable block to the transaction ledger.
// ============================================================================

// routes/files.js
const express = require('express');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const { getDB } = require('../db/database');
const { requireAuth, requireNotSuspended } = require('../middleware/auth');
const { hashBuffer, encryptFileEnvelope, encryptFileForRecipients } = require('../utils/crypto');
const { addBlock } = require('../utils/blockchain');
const { computeExpiry, isFileExpired } = require('../utils/expiry');

const router = express.Router();

// Configure file upload buffer limit in memory (50MB max file size)
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 50 * 1024 * 1024 } });

// Directory where encrypted files (.enc) are written to disk
const UPLOAD_DIR = path.join(__dirname, '..', 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

/**
 * Pushes real-time audit notifications to connected administrators via Socket.IO.
 */
function broadcastTraffic(req, payload) {
  req.app.get('io').to('admin-room').emit('file-traffic', { ...payload, timestamp: new Date().toISOString() });
}

/**
 * Fetches the public RSA key for a specific user email from the public_keys directory.
 */
async function getPublicKey(db, email) {
  const row = await db.get('SELECT publicKeyPem FROM public_keys WHERE email = ?', [email]);
  return row ? row.publicKeyPem : null;
}

/**
 * Checks if a user is an active member of a specified group folder.
 */
async function isGroupMember(db, groupId, email) {
  if (!groupId) return false;
  const row = await db.get('SELECT 1 FROM group_members WHERE groupId = ? AND memberEmail = ?', [groupId, email]);
  return !!row;
}

/**
 * Authorization Check: Evaluates whether a user has legitimate access rights to a file.
 * Returns true if the user is the file owner, direct recipient, or a group member.
 */
async function canAccessFile(db, fileRow, email) {
  if (fileRow.ownerEmail === email || fileRow.receiverEmail === email) return true;
  if (fileRow.groupId) return isGroupMember(db, fileRow.groupId, email);
  return false;
}

/**
 * Determines target public key for envelope encryption.
 */
async function getEncryptionTargetKey(db, fileRow) {
  const targetEmail = fileRow.receiverEmail || fileRow.ownerEmail;
  return { targetEmail, publicKey: await getPublicKey(db, targetEmail) };
}

/**
 * Encrypts file buffer using AES-256-GCM, wraps AES key with target RSA Public Key,
 * writes encrypted file to disk, and saves version record to database.
 */
async function saveVersion(db, { fileId, versionNumber, fileBuffer, publicKey, uploadedBy }) {
  const fileHash = hashBuffer(fileBuffer); // SHA-256 content fingerprint
  const { encryptedFile, iv, authTag, encryptedKey } = encryptFileEnvelope(fileBuffer, publicKey);
  const storedName = `${crypto.randomUUID()}.enc`; // Random filename prevents filename guessing attacks
  fs.writeFileSync(path.join(UPLOAD_DIR, storedName), encryptedFile);

  await db.run(
    `INSERT INTO file_versions (fileId, versionNumber, storedName, fileHash, fileSize, iv, authTag, encryptedKey, uploadedBy)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [fileId, versionNumber, storedName, fileHash, fileBuffer.length, iv, authTag, encryptedKey, uploadedBy]
  );

  return { fileHash, fileSize: fileBuffer.length };
}

/**
 * Group Variant: Encrypts file ONCE with AES-256-GCM, then wraps AES key
 * separately for EACH active group member's RSA Public Key.
 */
async function saveGroupVersion(db, { fileId, versionNumber, fileBuffer, members, uploadedBy }) {
  const fileHash = hashBuffer(fileBuffer);
  const { encryptedFile, iv, authTag, wrappedKeys } = encryptFileForRecipients(fileBuffer, members);
  const storedName = `${crypto.randomUUID()}.enc`;
  fs.writeFileSync(path.join(UPLOAD_DIR, storedName), encryptedFile);

  const versionResult = await db.run(
    `INSERT INTO file_versions (fileId, versionNumber, storedName, fileHash, fileSize, iv, authTag, encryptedKey, uploadedBy)
     VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?)`,
    [fileId, versionNumber, storedName, fileHash, fileBuffer.length, iv, authTag, uploadedBy]
  );

  for (const { email, encryptedKey } of wrappedKeys) {
    await db.run(
      'INSERT INTO version_keys (versionId, recipientEmail, encryptedKey) VALUES (?, ?, ?)',
      [versionResult.lastID, email, encryptedKey]
    );
  }

  return { fileHash, fileSize: fileBuffer.length };
}

// ============================================================================
// ROUTE: POST /api/files/upload (Personal File Upload)
// ============================================================================
// Encrypts file for uploader's own RSA key. Appends transaction to blockchain.
// ============================================================================
router.post('/upload', requireAuth, requireNotSuspended, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file provided' });

    const db = await getDB();
    const ownerEmail = req.user.email;

    const ownerPublicKey = await getPublicKey(db, ownerEmail);
    if (!ownerPublicKey) return res.status(400).json({ error: 'No public key on record for your account' });

    let expiresAt;
    try {
      ({ expiresAt } = computeExpiry(req.body.expiryType || 'none', req.body.customHours));
    } catch (e) {
      return res.status(400).json({ error: e.message });
    }

    const fileResult = await db.run(
      `INSERT INTO files (originalName, ownerEmail, receiverEmail, expiryType, expiresAt)
       VALUES (?, ?, NULL, ?, ?)`,
      [req.file.originalname, ownerEmail, req.body.expiryType || 'none', expiresAt]
    );
    const fileId = fileResult.lastID;

    const { fileHash } = await saveVersion(db, {
      fileId, versionNumber: 1, fileBuffer: req.file.buffer, publicKey: ownerPublicKey, uploadedBy: ownerEmail
    });

    // Immutable ledger audit entry
    const block = await addBlock({ action: 'upload', sender: ownerEmail, receiver: null, fileHash });
    broadcastTraffic(req, { action: 'upload', email: ownerEmail, fileName: req.file.originalname, size: req.file.size });

    res.status(201).json({ message: 'File uploaded and encrypted successfully', fileId, fileHash, block });
  } catch (err) {
    console.error('Upload error:', err);
    res.status(500).json({ error: 'Upload failed' });
  }
});

// ============================================================================
// ROUTE: POST /api/files/send (Direct 1:1 File Transfer)
// ============================================================================
// Encrypts file with recipient's public key so ONLY recipient can decrypt it.
// ============================================================================
router.post('/send', requireAuth, requireNotSuspended, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file provided' });

    const { recipientEmail, expiryType, customHours } = req.body;
    if (!recipientEmail) return res.status(400).json({ error: 'Recipient email is required' });

    const db = await getDB();
    const senderEmail = req.user.email;

    if (recipientEmail === senderEmail) {
      return res.status(400).json({ error: 'Use Upload File to store files for yourself' });
    }

    const recipientExists = await db.get('SELECT email FROM users WHERE email = ?', [recipientEmail]);
    if (!recipientExists) return res.status(404).json({ error: 'No Data Chain account found for that email' });

    const recipientPublicKey = await getPublicKey(db, recipientEmail);
    if (!recipientPublicKey) return res.status(400).json({ error: 'Recipient has no public key on record' });

    let expiresAt;
    try {
      ({ expiresAt } = computeExpiry(expiryType || 'none', customHours));
    } catch (e) {
      return res.status(400).json({ error: e.message });
    }

    const fileResult = await db.run(
      `INSERT INTO files (originalName, ownerEmail, receiverEmail, expiryType, expiresAt)
       VALUES (?, ?, ?, ?, ?)`,
      [req.file.originalname, senderEmail, recipientEmail, expiryType || 'none', expiresAt]
    );
    const fileId = fileResult.lastID;

    const { fileHash } = await saveVersion(db, {
      fileId, versionNumber: 1, fileBuffer: req.file.buffer, publicKey: recipientPublicKey, uploadedBy: senderEmail
    });

    const block = await addBlock({ action: 'send', sender: senderEmail, receiver: recipientEmail, fileHash });

    // Notify recipient in real-time
    const io = req.app.get('io');
    io.to(recipientEmail).emit('file-received', { fileId, from: senderEmail, originalName: req.file.originalname });
    broadcastTraffic(req, { action: 'send', email: senderEmail, to: recipientEmail, fileName: req.file.originalname, size: req.file.size });

    res.status(201).json({ message: `File sent to ${recipientEmail}`, fileId, fileHash, block });
  } catch (err) {
    console.error('Send error:', err);
    res.status(500).json({ error: 'Send failed' });
  }
});

// ============================================================================
// ROUTE: POST /api/files/:id/version (Add New Encrypted Version)
// ============================================================================
// Adds a new version to an existing file family without touching older versions.
// ============================================================================
router.post('/:id/version', requireAuth, requireNotSuspended, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file provided' });

    const db = await getDB();
    const email = req.user.email;
    const fileRow = await db.get('SELECT * FROM files WHERE id = ?', [req.params.id]);

    if (!fileRow) return res.status(404).json({ error: 'File not found' });

    const lastVersion = await db.get(
      'SELECT MAX(versionNumber) as maxV FROM file_versions WHERE fileId = ?', [fileRow.id]
    );
    const nextVersion = (lastVersion?.maxV || 0) + 1;

    let fileHash;

    if (fileRow.groupId) {
      if (!(await isGroupMember(db, fileRow.groupId, email))) {
        return res.status(403).json({ error: 'You are not a member of this group' });
      }
      const members = await db.all(
        `SELECT gm.memberEmail as email, pk.publicKeyPem as publicKey
         FROM group_members gm JOIN public_keys pk ON pk.email = gm.memberEmail
         WHERE gm.groupId = ?`,
        [fileRow.groupId]
      );
      ({ fileHash } = await saveGroupVersion(db, {
        fileId: fileRow.id, versionNumber: nextVersion, fileBuffer: req.file.buffer, members, uploadedBy: email
      }));

      const io = req.app.get('io');
      for (const m of members) {
        if (m.email !== email) {
          io.to(m.email).emit('file-received', {
            fileId: fileRow.id, from: email, originalName: req.file.originalname, isNewVersion: true
          });
        }
      }
    } else {
      if (fileRow.ownerEmail !== email) {
        return res.status(403).json({ error: 'Only the file owner can add a new version' });
      }
      const { targetEmail, publicKey } = await getEncryptionTargetKey(db, fileRow);
      if (!publicKey) return res.status(400).json({ error: `No public key on record for ${targetEmail}` });

      ({ fileHash } = await saveVersion(db, {
        fileId: fileRow.id, versionNumber: nextVersion, fileBuffer: req.file.buffer, publicKey, uploadedBy: email
      }));

      if (fileRow.receiverEmail) {
        const io = req.app.get('io');
        io.to(fileRow.receiverEmail).emit('file-received', {
          fileId: fileRow.id, from: email, originalName: req.file.originalname, isNewVersion: true
        });
      }
    }

    await db.run('UPDATE files SET originalName = ? WHERE id = ?', [req.file.originalname, fileRow.id]);

    const block = await addBlock({
      action: 'version', sender: email, receiver: fileRow.receiverEmail || (fileRow.groupId ? `group:${fileRow.groupId}` : null), fileHash
    });
    broadcastTraffic(req, { action: 'version', email, fileName: req.file.originalname, versionNumber: nextVersion });

    res.status(201).json({
      message: `Version ${nextVersion} added`,
      fileId: fileRow.id,
      versionNumber: nextVersion,
      fileHash,
      block
    });
  } catch (err) {
    console.error('Add version error:', err);
    res.status(500).json({ error: 'Failed to add new version' });
  }
});

// GET /api/files/:id/versions (Version History)
router.get('/:id/versions', requireAuth, async (req, res) => {
  const db = await getDB();
  const email = req.user.email;
  const fileRow = await db.get('SELECT * FROM files WHERE id = ?', [req.params.id]);

  if (!fileRow) return res.status(404).json({ error: 'File not found' });
  if (!(await canAccessFile(db, fileRow, email))) {
    return res.status(403).json({ error: 'You do not have access to this file' });
  }

  const versions = await db.all(
    `SELECT versionNumber, fileHash, fileSize, uploadedBy, createdAt
     FROM file_versions WHERE fileId = ? ORDER BY versionNumber ASC`,
    [fileRow.id]
  );

  res.json({ fileId: fileRow.id, originalName: fileRow.originalName, versions });
});

// GET /api/files/my-files (List accessible files)
router.get('/my-files', requireAuth, async (req, res) => {
  const db = await getDB();
  const email = req.user.email;

  const rows = await db.all(
    `SELECT f.id, f.originalName, f.ownerEmail, f.receiverEmail, f.groupId, f.expiryType, f.expiresAt,
            f.downloadCount, f.isExpired, f.createdAt,
            v.fileHash, v.fileSize, v.versionNumber as latestVersion,
            g.name as groupName
     FROM files f
     JOIN file_versions v ON v.fileId = f.id
     LEFT JOIN groups g ON g.id = f.groupId
     WHERE (f.ownerEmail = ? OR f.receiverEmail = ? OR f.groupId IN (SELECT groupId FROM group_members WHERE memberEmail = ?))
       AND v.versionNumber = (SELECT MAX(versionNumber) FROM file_versions WHERE fileId = f.id)
     ORDER BY f.createdAt DESC`,
    [email, email, email]
  );

  const files = rows.map((row) => ({
    ...row,
    direction: row.groupId ? 'group' : (row.ownerEmail === email ? (row.receiverEmail ? 'sent' : 'personal') : 'received'),
    expired: isFileExpired(row),
    canManage: row.ownerEmail === email || !!row.groupId
  }));

  res.json({ files });
});

// ============================================================================
// ROUTE: GET /api/files/:id/download (Download Encrypted Payload)
// ============================================================================
// SECURITY CHECKS:
//   1. Authentication Check (`requireAuth`)
//   2. Account Suspension Check (`requireNotSuspended`)
//   3. File Authorization Check (`canAccessFile`) -> logs failure if unauthorized
//   4. Expiration Check (`isFileExpired`) -> returns HTTP 410 Gone if expired
//   5. Retrieves encrypted key bundle specific to requester
//   6. Writes audit logs & blockchain transaction entry
// ============================================================================
router.get('/:id/download', requireAuth, requireNotSuspended, async (req, res) => {
  const db = await getDB();
  const email = req.user.email;
  const fileRow = await db.get('SELECT * FROM files WHERE id = ?', [req.params.id]);

  if (!fileRow) return res.status(404).json({ error: 'File not found' });

  // Authorization Check
  if (!(await canAccessFile(db, fileRow, email))) {
    await db.run('INSERT INTO access_logs (fileId, userEmail, action, detail) VALUES (?, ?, ?, ?)',
      [fileRow.id, email, 'denied', 'not owner, receiver, or group member']);
    return res.status(403).json({ error: 'You do not have access to this file' });
  }

  // Time-Based Access Expiration Check
  if (isFileExpired(fileRow)) {
    if (!fileRow.isExpired) await db.run('UPDATE files SET isExpired = 1 WHERE id = ?', [fileRow.id]);
    await db.run('INSERT INTO access_logs (fileId, userEmail, action, detail) VALUES (?, ?, ?, ?)',
      [fileRow.id, email, 'denied', 'expired']);
    return res.status(410).json({ error: 'Your access window for this file has expired' });
  }

  const requestedVersion = req.query.version ? Number(req.query.version) : null;
  const versionRow = requestedVersion
    ? await db.get('SELECT * FROM file_versions WHERE fileId = ? AND versionNumber = ?', [fileRow.id, requestedVersion])
    : await db.get('SELECT * FROM file_versions WHERE fileId = ? ORDER BY versionNumber DESC LIMIT 1', [fileRow.id]);

  if (!versionRow) return res.status(404).json({ error: 'That version does not exist' });

  // Retrieve user's wrapped RSA-AES key
  let encryptedKey = versionRow.encryptedKey;
  if (fileRow.groupId) {
    const keyRow = await db.get(
      'SELECT encryptedKey FROM version_keys WHERE versionId = ? AND recipientEmail = ?',
      [versionRow.id, email]
    );
    if (!keyRow) {
      return res.status(403).json({ error: 'No decryption key on record for you for this version — you may have joined the group after this version was added.' });
    }
    encryptedKey = keyRow.encryptedKey;
  }

  const encryptedFile = fs.readFileSync(path.join(UPLOAD_DIR, versionRow.storedName));

  // Update audit tracking logs
  await db.run('UPDATE files SET downloadCount = downloadCount + 1 WHERE id = ?', [fileRow.id]);
  await db.run('INSERT INTO access_logs (fileId, userEmail, action, detail) VALUES (?, ?, ?, ?)',
    [fileRow.id, email, 'download', `success (v${versionRow.versionNumber})`]);
  await addBlock({ action: 'download', sender: fileRow.ownerEmail, receiver: email, fileHash: versionRow.fileHash });
  broadcastTraffic(req, { action: 'download', email, fileName: fileRow.originalName, versionNumber: versionRow.versionNumber });

  res.json({
    originalName: fileRow.originalName,
    versionNumber: versionRow.versionNumber,
    fileHash: versionRow.fileHash,
    iv: versionRow.iv,
    authTag: versionRow.authTag,
    encryptedKey,
    encryptedFile: encryptedFile.toString('base64')
  });
});

// PATCH /api/files/:id/access (Update Access Duration Window)
router.patch('/:id/access', requireAuth, async (req, res) => {
  try {
    const db = await getDB();
    const email = req.user.email;
    const fileRow = await db.get('SELECT * FROM files WHERE id = ?', [req.params.id]);

    if (!fileRow) return res.status(404).json({ error: 'File not found' });
    const allowed = fileRow.ownerEmail === email || (fileRow.groupId && await isGroupMember(db, fileRow.groupId, email));
    if (!allowed) {
      return res.status(403).json({ error: 'Only the file owner or a group member can change access settings' });
    }

    const { expiryType, customHours } = req.body;
    let expiresAt;
    try {
      ({ expiresAt } = computeExpiry(expiryType || 'none', customHours));
    } catch (e) {
      return res.status(400).json({ error: e.message });
    }

    await db.run(
      'UPDATE files SET expiryType = ?, expiresAt = ?, isExpired = 0 WHERE id = ?',
      [expiryType || 'none', expiresAt, fileRow.id]
    );

    const latestVersion = await db.get(
      'SELECT fileHash FROM file_versions WHERE fileId = ? ORDER BY versionNumber DESC LIMIT 1',
      [fileRow.id]
    );
    const block = await addBlock({
      action: 'access-updated',
      sender: email,
      receiver: fileRow.receiverEmail || null,
      fileHash: latestVersion ? latestVersion.fileHash : fileRow.id.toString()
    });

    res.json({ message: 'Access window updated', expiryType: expiryType || 'none', expiresAt, block });
  } catch (err) {
    console.error('Update access error:', err);
    res.status(500).json({ error: 'Failed to update access settings' });
  }
});

// ============================================================================
// ROUTE: DELETE /api/files/:id (Delete Personal File)
// ============================================================================
// Permanently removes a file and all its versions from disk and database.
// Only the file owner can delete their own personal files.
// A blockchain entry is logged for auditability.
// ============================================================================
router.delete('/:id', requireAuth, requireNotSuspended, async (req, res) => {
  try {
    const db = await getDB();
    const email = req.user.email;
    const fileRow = await db.get('SELECT * FROM files WHERE id = ?', [req.params.id]);

    if (!fileRow) return res.status(404).json({ error: 'File not found' });

    // Only the file owner can delete
    if (fileRow.ownerEmail !== email) {
      return res.status(403).json({ error: 'Only the file owner can delete this file' });
    }

    // Fetch all version records so we can remove encrypted files from disk
    const versions = await db.all(
      'SELECT storedName, fileHash FROM file_versions WHERE fileId = ?',
      [fileRow.id]
    );

    // Delete encrypted files from disk
    for (const v of versions) {
      const filePath = path.join(UPLOAD_DIR, v.storedName);
      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
      }
    }

    // Get the latest version hash for the blockchain entry
    const latestHash = versions.length > 0
      ? versions[versions.length - 1].fileHash
      : fileRow.id.toString();

    // Delete file record (cascades to file_versions, version_keys, access_logs)
    await db.run('DELETE FROM files WHERE id = ?', [fileRow.id]);

    // Log the deletion to the blockchain for auditability
    const block = await addBlock({
      action: 'delete',
      sender: email,
      receiver: fileRow.receiverEmail || null,
      fileHash: latestHash
    });

    // Log to access_logs (file is already deleted, so we pass null for fileId)
    await db.run(
      'INSERT INTO access_logs (fileId, userEmail, action, detail) VALUES (?, ?, ?, ?)',
      [null, email, 'delete', `Deleted file "${fileRow.originalName}" (id: ${fileRow.id})`]
    );

    broadcastTraffic(req, {
      action: 'delete',
      email,
      fileName: fileRow.originalName,
      size: 0
    });

    res.json({
      message: `File "${fileRow.originalName}" has been permanently deleted`,
      block
    });
  } catch (err) {
    console.error('Delete file error:', err);
    res.status(500).json({ error: 'Failed to delete file' });
  }
});

module.exports = router;

