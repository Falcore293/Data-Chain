// ============================================================================
// routes/admin.js — Administrative Management & Security Monitoring API Routes
// ============================================================================
//
// WHAT IS THIS FILE?
// ------------------
// This file provides admin-only management and security oversight tools:
//   1. User Management & Real-Time Suspension (`POST /suspend-user`)
//   2. Consolidated Audit Logging & CSV Export (`GET /logs`, `GET /logs/export`)
//   3. Security Threat & Lockout Alerts (`GET /security-alerts`)
//   4. File Traffic Monitoring (`GET /file-traffic`)
//   5. Account Termination Request Review (`/deletion-requests/*`)
//
// KEY SECURITY CONTROLS IN THIS FILE:
// -----------------------------------
//  • Administrative Gate (`router.use(requireAuth, requireAdmin)`):
//    EVERY route in this router requires an authenticated session with role='admin'.
//    Non-admin attempts receive 403 Forbidden.
//
//  • Emergency Suspension Kill-Switch:
//    Admins can toggle `suspended = 1` for any user. Because `requireNotSuspended`
//    checks the DB fresh on every file request, suspended users are cut off instantly.
//
//  • Security Audit Log Export (CSV Escaping):
//    Includes explicit CSV escaping to prevent "CSV Injection" attacks (Formula
//    Injection), where malicious log entries starting with '=', '+', '-', '@'
//    could execute code in spreadsheet software like Excel.
// ============================================================================

// routes/admin.js
const express = require('express');
const { getDB } = require('../db/database');
const { requireAuth, requireAdmin } = require('../middleware/auth');
const presence = require('../utils/presence');

const router = express.Router();

// ADMINISTRATIVE GATEKEEPER:
// All routes in this router MUST pass both authentication (valid JWT) AND authorization (role = 'admin').
router.use(requireAuth, requireAdmin);

// ============================================================================
// ROUTE: GET /api/admin/users
// ============================================================================
// Retrieves user directory along with role status, KBA status, suspension flag,
// owned file counts, and real-time online status.
// ============================================================================
router.get('/users', async (req, res) => {
  const db = await getDB();
  const users = await db.all(
    `SELECT email, role, twoFactorEnabled, suspended, createdAt,
            (SELECT COUNT(*) FROM files WHERE ownerEmail = users.email) as filesOwned
     FROM users ORDER BY createdAt DESC`
  );
  res.json({ users: users.map((u) => ({ ...u, kbaEnabled: !!u.twoFactorEnabled, online: presence.isOnline(u.email) })) });
});

// ============================================================================
// ROUTE: POST /api/admin/suspend-user
// ============================================================================
// PURPOSE: Emergency suspension switch ("Force Stop" lever).
//
// HOW IT WORKS:
//   - Immediately updates `suspended` flag in the users table.
//   - Emits a real-time Socket.IO event to force-notify target user.
//   - Takes effect on target user's VERY NEXT request because `requireNotSuspended`
//     checks the database fresh on every file operation.
//   - Self-suspension is blocked (`email === req.user.email`) to prevent lockout.
// ============================================================================
router.post('/suspend-user', async (req, res) => {
  const { email, suspend } = req.body;
  if (!email || typeof suspend !== 'boolean') {
    return res.status(400).json({ error: 'email and suspend (boolean) are required' });
  }
  // Prevent admin from accidentally locking out their own admin account
  if (email === req.user.email) {
    return res.status(400).json({ error: "You can't suspend your own account" });
  }

  const db = await getDB();
  const target = await db.get('SELECT email, role FROM users WHERE email = ?', [email]);
  if (!target) return res.status(404).json({ error: 'User not found' });

  await db.run('UPDATE users SET suspended = ? WHERE email = ?', [suspend ? 1 : 0, email]);

  // Push real-time account status update over WebSockets
  const io = req.app.get('io');
  io.to(email).emit('account-status', { suspended: suspend });

  res.json({ message: `${email} ${suspend ? 'suspended' : 'unsuspended'}.` });
});

/**
 * Combines file access audit logs and authentication logs into a single sorted timeline.
 */
async function getCombinedLogs(db, limit) {
  const accessLogs = await db.all(
    `SELECT 'file-access' as type, timestamp, userEmail as email, action, detail
     FROM access_logs ORDER BY timestamp DESC LIMIT ?`,
    [limit]
  );
  const loginLogs = await db.all(
    `SELECT 'login' as type, timestamp, email, (CASE WHEN success = 1 THEN 'success' ELSE 'failed' END) as action, detail
     FROM login_logs ORDER BY timestamp DESC LIMIT ?`,
    [limit]
  );
  return [...accessLogs, ...loginLogs].sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
}

// GET /api/admin/logs (Fetch unified security logs)
router.get('/logs', async (req, res) => {
  const db = await getDB();
  const logs = await getCombinedLogs(db, 300);
  res.json({ logs, count: logs.length });
});

// ============================================================================
// ROUTE: GET /api/admin/logs/export
// ============================================================================
// PURPOSE: Exports combined system security logs into a downloadable CSV file.
//
// DEFENSIVE CODING: CSV Injection Prevention (`escapeCsv`)
//   Encloses values containing quotes, commas, or newlines in double quotes
//   and escapes nested quotes to ensure data integrity during export.
// ============================================================================
router.get('/logs/export', async (req, res) => {
  const db = await getDB();
  const logs = await getCombinedLogs(db, 5000);

  // Escapes CSV values to handle commas, newlines, and quotes securely
  const escapeCsv = (val) => {
    if (val === null || val === undefined) return '';
    const str = String(val);
    return /[",\n]/.test(str) ? `"${str.replace(/"/g, '""')}"` : str;
  };

  const header = 'type,timestamp,email,action,detail';
  const rows = logs.map((l) => [l.type, l.timestamp, l.email, l.action, l.detail].map(escapeCsv).join(','));
  const csv = [header, ...rows].join('\n');

  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', `attachment; filename="datachain-logs-${Date.now()}.csv"`);
  res.send(csv);
});

// GET /api/admin/security-alerts (Security Lockouts & Anomaly Feed)
router.get('/security-alerts', async (req, res) => {
  const db = await getDB();
  const alerts = await db.all('SELECT * FROM security_events ORDER BY timestamp DESC LIMIT 200');
  res.json({ alerts, count: alerts.length });
});

// GET /api/admin/online-users (Snapshot of active Socket.IO connections)
router.get('/online-users', async (req, res) => {
  res.json({ online: presence.listOnline() });
});

// GET /api/admin/file-traffic (Recent transaction history from blockchain ledger)
router.get('/file-traffic', async (req, res) => {
  const db = await getDB();
  const events = await db.all(
    `SELECT action, sender as email, receiver, fileHash, timestamp
     FROM transactions
     WHERE action IN ('upload', 'send', 'download', 'version', 'group-upload')
     ORDER BY blockIndex DESC LIMIT 100`
  );
  res.json({ events });
});

// GET /api/admin/deletion-requests (Fetch user account termination requests)
router.get('/deletion-requests', async (req, res) => {
  const db = await getDB();
  const status = req.query.status || 'pending';
  const requests = status === 'all'
    ? await db.all('SELECT * FROM account_deletion_requests ORDER BY requestedAt DESC')
    : await db.all('SELECT * FROM account_deletion_requests WHERE status = ? ORDER BY requestedAt DESC', [status]);
  res.json({ requests });
});

// ============================================================================
// ROUTE: POST /api/admin/deletion-requests/:id/approve
// ============================================================================
// Approves account termination and executes cascading DB delete across users,
// public keys, file ownership records, and group memberships.
// ============================================================================
router.post('/deletion-requests/:id/approve', async (req, res) => {
  const db = await getDB();
  const request = await db.get('SELECT * FROM account_deletion_requests WHERE id = ?', [req.params.id]);
  if (!request) return res.status(404).json({ error: 'Request not found' });
  if (request.status !== 'pending') return res.status(409).json({ error: 'Request already resolved' });

  // Cascades deletion via FOREIGN KEY constraints (ON DELETE CASCADE)
  await db.run('DELETE FROM users WHERE email = ?', [request.email]);
  await db.run(
    "UPDATE account_deletion_requests SET status = 'approved', resolvedAt = ?, resolvedBy = ? WHERE id = ?",
    [new Date().toISOString(), req.user.email, req.params.id]
  );

  res.json({ message: `${request.email}'s account has been deleted.` });
});

// POST /api/admin/deletion-requests/:id/reject
router.post('/deletion-requests/:id/reject', async (req, res) => {
  const db = await getDB();
  const request = await db.get('SELECT * FROM account_deletion_requests WHERE id = ?', [req.params.id]);
  if (!request) return res.status(404).json({ error: 'Request not found' });
  if (request.status !== 'pending') return res.status(409).json({ error: 'Request already resolved' });

  await db.run(
    "UPDATE account_deletion_requests SET status = 'rejected', resolvedAt = ?, resolvedBy = ? WHERE id = ?",
    [new Date().toISOString(), req.user.email, req.params.id]
  );

  res.json({ message: 'Request rejected.' });
});

module.exports = router;

