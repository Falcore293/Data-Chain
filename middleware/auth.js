// ============================================================================
// middleware/auth.js — Authentication & Authorization Middleware
// ============================================================================
//
// WHAT IS THIS FILE?
// ------------------
// This file contains "middleware" functions — code that runs BETWEEN a
// request arriving at the server and the actual route handler processing it.
// Think of middleware as security guards at a building entrance:
//
//   requireAuth        → "Show me your ID badge" (are you logged in?)
//   requireAdmin       → "Is your badge marked 'admin'?" (are you an admin?)
//   requireNotSuspended → "Let me check if your access has been revoked"
//
// If ANY of these checks fail, the request is rejected immediately and
// the route handler never runs. This is a fundamental security pattern
// called "fail-closed" — if we can't verify you, you're denied by default.
//
// SECURITY CONCEPTS:
// ------------------
//  • Authentication (authn) — proving WHO you are (requireAuth)
//  • Authorization (authz)  — checking WHAT you're allowed to do
//                              (requireAdmin, requireNotSuspended)
//  • JWT (JSON Web Token)   — a digitally signed token that proves identity
//  • Bearer Token Pattern   — sending credentials via the Authorization header
//  • Role-Based Access Control (RBAC) — permissions based on user roles
// ============================================================================

// middleware/auth.js

// jsonwebtoken (JWT) library: used to verify the digital signature on
// tokens. A JWT is a compact, URL-safe string that contains a user's
// identity (email, role) and is signed with a secret key known only to
// the server. When the user logs in, they receive a JWT; on every
// subsequent request, they send it back in the "Authorization" header.
// The server verifies the signature to confirm the token hasn't been
// tampered with and hasn't expired.
const jwt = require('jsonwebtoken');

// Database connection — needed only for the suspension check, which
// queries the users table in real time.
const { getDB } = require('../db/database');

// ============================================================================
// MIDDLEWARE 1: requireAuth
// ============================================================================
// PURPOSE: Verifies that the request includes a valid JWT token.
//          This is the FIRST security gate — it confirms the user is logged in.
//
// HOW IT WORKS:
//   1. Looks for the "Authorization" header in the request
//      (format: "Bearer <token>")
//   2. Extracts the token string
//   3. Verifies the token's digital signature using the server's JWT_SECRET
//   4. If valid, attaches the decoded user info (email, role) to req.user
//      so downstream handlers can use it
//   5. If invalid or missing, returns 401 Unauthorized
//
// ANALOGY:
//   It's like showing your wristband at a festival. The wristband (JWT)
//   was given to you when you entered (logged in). At every stage, staff
//   check that your wristband is genuine and hasn't expired. If you don't
//   have one or it's fake, you're turned away.
//
// WHY 401 (not 403)?
//   401 = "Unauthenticated" — we don't know who you are
//   403 = "Forbidden" — we know who you are, but you lack permission
// ============================================================================
function requireAuth(req, res, next) {
  // Look for the Authorization header. If not present, default to empty string.
  const header = req.headers.authorization || '';

  // The standard format is "Bearer <token>". Extract just the token part.
  // If the header doesn't start with "Bearer ", token will be null.
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;

  // No token at all → reject immediately.
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  try {
    // jwt.verify() does two things:
    //   1. Checks the cryptographic signature (was this token signed by OUR server?)
    //   2. Checks the expiration time (has this token expired?)
    // If either check fails, it throws an error.
    // If both pass, it returns the decoded payload: { email, role, iat, exp }
    const payload = jwt.verify(token, process.env.JWT_SECRET);

    // Attach the verified user identity to the request object so that
    // subsequent middleware and route handlers can access it.
    req.user = payload; // { email, role }

    // Call next() to pass control to the next middleware or route handler.
    // Without this call, the request would hang forever.
    next();
  } catch (err) {
    // The token was invalid (tampered with, wrong secret) or expired.
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// ============================================================================
// MIDDLEWARE 2: requireAdmin
// ============================================================================
// PURPOSE: Ensures the authenticated user has the 'admin' role.
//          MUST be chained AFTER requireAuth (which sets req.user).
//
// HOW IT WORKS:
//   Simply checks req.user.role (set by requireAuth from the JWT payload).
//   The role was baked into the JWT at login time based on the users table.
//   This means no extra database query is needed — it's a fast, in-memory
//   check. The tradeoff is that if an admin's role is changed in the DB,
//   they'd need to log out and back in for the JWT to reflect the new role.
//
// SECURITY PATTERN: Role-Based Access Control (RBAC)
//   Users are assigned roles (e.g., 'user', 'admin'), and permissions
//   are granted based on those roles rather than on individual users.
//   This is simpler to manage than per-user permissions.
// ============================================================================

// Chain after requireAuth. Role comes straight from the JWT (set at
// login time from the users table), so this is a cheap check with no
// extra DB hit.
function requireAdmin(req, res, next) {
  // The ?. is "optional chaining" — if req.user is null/undefined,
  // this safely returns undefined instead of throwing an error.
  if (req.user?.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
}

// ============================================================================
// MIDDLEWARE 3: requireNotSuspended
// ============================================================================
// PURPOSE: Checks whether the user's account has been suspended by an admin.
//          Used on file-operation routes (upload, send, download, version)
//          so that suspension takes effect IMMEDIATELY, not just at next login.
//
// WHY CHECK THE DATABASE EVERY TIME?
//   The JWT contains the user's role, but NOT their suspension status.
//   This is deliberate: if suspension were stored in the JWT, a suspended
//   user could keep operating until their token expired (up to 2 hours).
//   By checking the database on every file operation, the admin's "force
//   stop" lever works instantly — the very next request after suspension
//   will be denied.
//
// TRADEOFF:
//   This adds a database query to every file operation, which is slightly
//   slower than reading from the JWT. But for a security-critical feature
//   like suspension, immediacy is more important than speed.
//
// ANALOGY:
//   Imagine a hotel key card. Your name and room number are on the card
//   (like a JWT), but the hotel can ALSO disable your card remotely at
//   the front desk. Every time you tap the card, the door lock checks
//   with the front desk (database) whether your card is still active.
// ============================================================================

// Chain after requireAuth on file-operation routes only (upload, send,
// download, version). This is the actual mechanism behind the admin
// "force stop" lever from the File Traffic panel: suspending a user
// takes effect on their very next request, not just their next login,
// since it's checked fresh from the DB every time rather than baked
// into the JWT.
async function requireNotSuspended(req, res, next) {
  try {
    // Open a database connection and look up the user's current
    // suspension status from the users table.
    const db = await getDB();
    const user = await db.get('SELECT suspended FROM users WHERE email = ?', [req.user.email]);

    // If the user's account is flagged as suspended, deny the request.
    if (user?.suspended) {
      return res.status(403).json({ error: 'Your account has been suspended by an administrator.' });
    }

    // Account is not suspended — allow the request to proceed.
    next();
  } catch (err) {
    // If the database query itself fails (e.g., DB is down), we return
    // a 500 Internal Server Error. We do NOT let the request through —
    // this is the "fail-closed" principle: if we can't verify, we deny.
    console.error('Suspension check error:', err);
    res.status(500).json({ error: 'Could not verify account status' });
  }
}

// Export all three middleware functions so they can be used in route files
// with: const { requireAuth, requireAdmin, requireNotSuspended } = require('../middleware/auth');
module.exports = { requireAuth, requireAdmin, requireNotSuspended };
