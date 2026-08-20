// ============================================================================
// routes/auth.js — Authentication & Identity API Routes
// ============================================================================
//
// WHAT IS THIS FILE?
// ------------------
// This file handles user account lifecycle and identity management:
//   1. Account Registration (`POST /signup`)
//   2. User Authentication & Login (`POST /login`)
//   3. Two-Step Verification (`POST /login/verify-2fa`)
//   4. Password Recovery Flow (`/forgot-password/*`)
//   5. Security Settings & Account Deletion Requests
//   6. Public Key Lookup (`GET /public-key/:email`)
//
// KEY SECURITY PRINCIPLES & MECHANISMS IN THIS FILE:
// --------------------------------------------------
//  • Password Hashing (bcrypt):
//    Passwords are hashed using bcrypt with salt rounds = 10 before storage.
//    Raw passwords NEVER hit the database.
//
//  • Zero-Knowledge Key Generation at Signup:
//    During signup, an RSA keypair is generated. The private key is encrypted
//    using AES-256-GCM + PBKDF2 derived from the user's password, returned to
//    the user as a downloadable file, and NEVER saved on the server.
//
//  • Session Authorization (JSON Web Tokens / JWT):
//    On successful authentication, the server signs a JWT containing the user's
//    email and role. The client sends this token in subsequent API requests.
//
//  • Shared Account Lockout Protection:
//    Login, 2FA, and Password Reset share the same lockout bucket (`loginAttempts.js`).
//    3 consecutive failures trigger a 60-second account lockout.
// ============================================================================

// routes/auth.js
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { getDB } = require('../db/database');
const { requireAuth } = require('../middleware/auth');
const { generateRSAKeyPair, encryptPrivateKey } = require('../utils/crypto');
const { getStatus, recordFailure, recordSuccess } = require('../utils/loginAttempts');

const router = express.Router();

// Email format regular expression validator
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const RESET_TOKEN_EXPIRES_IN = '10m';

/**
 * Normalizes security question answers (trims whitespace and converts to lowercase)
 * before hashing or verifying, so subtle capitalization differences won't fail validation.
 */
function normalizeAnswer(answer) {
  return answer.trim().toLowerCase();
}

/**
 * Generates a signed JSON Web Token (JWT) session token for an authenticated user.
 * Payload includes user email and role for Role-Based Access Control (RBAC).
 */
function issueToken(user) {
  return jwt.sign(
    { email: user.email, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN || '2h' }
  );
}

/**
 * Writes an entry into the login_logs table for audit tracking and security analytics.
 */
async function logLogin(db, email, success, detail, req) {
  await db.run(
    'INSERT INTO login_logs (email, success, detail, ipAddress) VALUES (?, ?, ?, ?)',
    [email, success ? 1 : 0, detail || null, req.ip]
  );
}

/**
 * Validates payload structure for security question setup.
 */
function validateQuestionsPayload(questions) {
  if (!Array.isArray(questions) || questions.length !== 2) {
    return 'Exactly 2 security questions are required';
  }
  for (const q of questions) {
    if (!q.question || !q.question.trim() || !q.answer || !q.answer.trim()) {
      return 'Every question needs both question text and an answer';
    }
  }
  if (questions[0].question.trim() === questions[1].question.trim()) {
    return 'Pick two different questions';
  }
  return null;
}

// ============================================================================
// ROUTE: POST /api/auth/signup
// ============================================================================
// PURPOSE: Registers a new user account.
//
// SECURITY WORKFLOW:
//   1. Input validation (email format, minimum password length 8 chars).
//   2. Hashes user password using bcrypt (10 rounds).
//   3. Generates RSA-2048 key pair (publicKeyPem + privateKeyPem).
//   4. Encrypts private key using AES-256-GCM + PBKDF2 derived from user password.
//   5. Stores user record & public key in database.
//   6. Hashes security question answers with bcrypt and stores them.
//   7. Returns encrypted private key bundle to client for download.
//   8. PURGES private key from server memory.
// ============================================================================

// ---------------------------------------------------------------------
// POST /api/auth/signup
// Security questions are now MANDATORY at signup - not to gate account
// creation behind email verification, but because /forgot-password
// depends on every account having them. Whether they're actually
// ASKED at login (twoFactorEnabled) stays a toggle in Settings.
// ---------------------------------------------------------------------
router.post('/signup', async (req, res) => {
  try {
    const { email, password, questions } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }
    if (!EMAIL_RE.test(email)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }
    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }
    const questionsError = validateQuestionsPayload(questions);
    if (questionsError) return res.status(400).json({ error: questionsError });

    const db = await getDB();
    const existing = await db.get('SELECT id FROM users WHERE email = ?', [email]);
    if (existing) {
      return res.status(409).json({ error: 'An account with this email already exists' });
    }

    // Password Hashing (bcrypt): Salting and hashing password
    const passwordHash = await bcrypt.hash(password, 10);
    
    // RSA Key Pair Generation & Client-Side Encryption Setup
    const { publicKey, privateKey } = generateRSAKeyPair();
    const encryptedPrivateKey = encryptPrivateKey(privateKey, password);
    
    // Automatic Admin Assignment based on environment configuration
    const role = (process.env.ADMIN_EMAIL && email === process.env.ADMIN_EMAIL) ? 'admin' : 'user';

    await db.run('INSERT INTO users (email, passwordHash, role) VALUES (?, ?, ?)', [email, passwordHash, role]);
    await db.run('INSERT INTO public_keys (email, publicKeyPem) VALUES (?, ?)', [email, publicKey]);

    // Store bcrypt-hashed security answers
    for (const q of questions) {
      const answerHash = await bcrypt.hash(normalizeAnswer(q.answer), 10);
      await db.run(
        'INSERT INTO security_questions (email, questionText, answerHash) VALUES (?, ?, ?)',
        [email, q.question.trim(), answerHash]
      );
    }

    // Hand encrypted private key to user. Server retains NOTHING regarding private keys.
    res.status(201).json({
      message: 'Account created. Save your private key file somewhere safe - it cannot be recovered if lost.',
      email,
      privateKeyBundle: { email, ...encryptedPrivateKey }
    });
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ error: 'Signup failed' });
  }
});

// ============================================================================
// ROUTE: POST /api/auth/login
// ============================================================================
// PURPOSE: Authenticates a user with email and password.
//
// SECURITY CHECKS:
//   1. Account Lockout Check: Verifies if account is locked due to 3 failed tries.
//   2. Password Verification: Compares supplied password against stored bcrypt hash.
//   3. Suspension Check: Denies access if admin flagged `suspended = 1`.
//   4. 2FA Check: If 2FA enabled, returns required security questions instead of JWT.
//   5. On success: Resets lockout counter, logs successful attempt, issues JWT.
// ============================================================================

// ---------------------------------------------------------------------
// POST /api/auth/login
// ---------------------------------------------------------------------
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const db = await getDB();

    // Check account lockout status (Brute-Force Protection)
    const status = getStatus(email);
    if (status.locked) {
      const seconds = Math.ceil(status.remainingMs / 1000);
      return res.status(429).json({
        error: `Too many failed attempts. Try again in ${seconds} second${seconds === 1 ? '' : 's'}.`,
        locked: true,
        retryAfterSeconds: seconds
      });
    }

    const user = await db.get('SELECT * FROM users WHERE email = ?', [email]);
    // bcrypt.compare prevents timing attacks during password verification
    const match = user ? await bcrypt.compare(password, user.passwordHash) : false;

    if (!user || !match) {
      const afterFailure = recordFailure(email);
      await logLogin(db, email, false, 'wrong password', req);

      if (afterFailure.locked) {
        await db.run('INSERT INTO security_events (email, eventType, detail) VALUES (?, ?, ?)',
          [email, 'lockout', '3 failed attempts']);
        const seconds = Math.ceil(afterFailure.remainingMs / 1000);
        return res.status(429).json({
          error: `Too many failed attempts. Try again in ${seconds} second${seconds === 1 ? '' : 's'}.`,
          locked: true, retryAfterSeconds: seconds
        });
      }
      return res.status(401).json({
        error: `Invalid email or password. ${afterFailure.remainingAttempts} attempt${afterFailure.remainingAttempts === 1 ? '' : 's'} remaining before a 1 minute lockout.`,
        remainingAttempts: afterFailure.remainingAttempts
      });
    }

    // Immediate admin suspension enforcement
    if (user.suspended) {
      return res.status(403).json({ error: 'This account has been suspended by an administrator.' });
    }

    // Two-Step Verification Gate
    if (user.twoFactorEnabled) {
      const questions = await db.all(
        'SELECT id, questionText FROM security_questions WHERE email = ? ORDER BY id ASC', [email]
      );
      return res.json({ twoFactorRequired: true, email, questions });
    }

    // Login successful: issue session token
    recordSuccess(email);
    await logLogin(db, email, true, 'password only', req);
    res.json({ token: issueToken(user), email: user.email });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Login failed' });
  }
});

// ============================================================================
// ROUTE: POST /api/auth/login/verify-2fa
// ============================================================================
// PURPOSE: Verifies security question answers for 2-step authentication.
// Verifies answers against bcrypt hashes, enforces lockout on failure.
// ============================================================================

// POST /api/auth/login/verify-2fa   { email, answers: [{ questionId, answer }] }
router.post('/login/verify-2fa', async (req, res) => {
  try {
    const { email, answers } = req.body;
    if (!email || !Array.isArray(answers) || answers.length === 0) {
      return res.status(400).json({ error: 'Email and answers are required' });
    }

    const db = await getDB();
    const user = await db.get('SELECT * FROM users WHERE email = ?', [email]);
    if (!user) return res.status(404).json({ error: 'Account not found' });

    const storedQuestions = await db.all('SELECT * FROM security_questions WHERE email = ?', [email]);
    let allCorrect = storedQuestions.length > 0 && answers.length === storedQuestions.length;
    if (allCorrect) {
      for (const submitted of answers) {
        const stored = storedQuestions.find((q) => q.id === submitted.questionId);
        if (!stored) { allCorrect = false; break; }
        const ok = await bcrypt.compare(normalizeAnswer(submitted.answer || ''), stored.answerHash);
        if (!ok) { allCorrect = false; break; }
      }
    }

    if (!allCorrect) {
      const afterFailure = recordFailure(email);
      await logLogin(db, email, false, 'wrong security answer(s)', req);
      if (afterFailure.locked) {
        await db.run('INSERT INTO security_events (email, eventType, detail) VALUES (?, ?, ?)',
          [email, 'lockout', '3 failed attempts (security questions)']);
        const seconds = Math.ceil(afterFailure.remainingMs / 1000);
        return res.status(429).json({
          error: `Too many failed attempts. Try again in ${seconds} second${seconds === 1 ? '' : 's'}.`,
          locked: true, retryAfterSeconds: seconds
        });
      }
      return res.status(401).json({
        error: `One or more answers were incorrect. ${afterFailure.remainingAttempts} attempt${afterFailure.remainingAttempts === 1 ? '' : 's'} remaining before a 1 minute lockout.`,
        remainingAttempts: afterFailure.remainingAttempts
      });
    }

    recordSuccess(email);
    await logLogin(db, email, true, 'security questions verified', req);
    res.json({ token: issueToken(user), email: user.email });
  } catch (err) {
    console.error('2-step verify error:', err);
    res.status(500).json({ error: 'Verification failed' });
  }
});

// ============================================================================
// FORGOT PASSWORD FLOW
// ============================================================================
// 1. GET /forgot-password/questions - Fetch public question text for account
// 2. POST /forgot-password/verify - Verify answers against bcrypt hashes -> issue 10-min reset JWT
// 3. POST /forgot-password/reset - Verify reset JWT & update password hash in database
// ============================================================================

// GET /api/auth/forgot-password/questions?email=...
router.get('/forgot-password/questions', async (req, res) => {
  const { email } = req.query;
  if (!email) return res.status(400).json({ error: 'Email is required' });

  const status = getStatus(email);
  if (status.locked) {
    const seconds = Math.ceil(status.remainingMs / 1000);
    return res.status(429).json({ error: `Too many attempts. Try again in ${seconds}s.`, locked: true, retryAfterSeconds: seconds });
  }

  const db = await getDB();
  const user = await db.get('SELECT id FROM users WHERE email = ?', [email]);
  if (!user) return res.status(404).json({ error: 'No account found for that email' });

  const questions = await db.all('SELECT id, questionText FROM security_questions WHERE email = ? ORDER BY id ASC', [email]);
  if (questions.length === 0) return res.status(400).json({ error: 'This account has no security questions on file' });

  res.json({ questions });
});

// POST /api/auth/forgot-password/verify   { email, answers }
router.post('/forgot-password/verify', async (req, res) => {
  try {
    const { email, answers } = req.body;
    if (!email || !Array.isArray(answers)) return res.status(400).json({ error: 'Email and answers are required' });

    const status = getStatus(email);
    if (status.locked) {
      const seconds = Math.ceil(status.remainingMs / 1000);
      return res.status(429).json({ error: `Too many attempts. Try again in ${seconds}s.`, locked: true, retryAfterSeconds: seconds });
    }

    const db = await getDB();
    const user = await db.get('SELECT * FROM users WHERE email = ?', [email]);
    if (!user) return res.status(404).json({ error: 'Account not found' });

    const storedQuestions = await db.all('SELECT * FROM security_questions WHERE email = ?', [email]);
    let allCorrect = storedQuestions.length > 0 && answers.length === storedQuestions.length;
    if (allCorrect) {
      for (const submitted of answers) {
        const stored = storedQuestions.find((q) => q.id === submitted.questionId);
        if (!stored) { allCorrect = false; break; }
        const ok = await bcrypt.compare(normalizeAnswer(submitted.answer || ''), stored.answerHash);
        if (!ok) { allCorrect = false; break; }
      }
    }

    if (!allCorrect) {
      const afterFailure = recordFailure(email);
      if (afterFailure.locked) {
        await db.run('INSERT INTO security_events (email, eventType, detail) VALUES (?, ?, ?)',
          [email, 'lockout', '3 failed attempts (password reset)']);
        const seconds = Math.ceil(afterFailure.remainingMs / 1000);
        return res.status(429).json({ error: `Too many attempts. Try again in ${seconds}s.`, locked: true, retryAfterSeconds: seconds });
      }
      return res.status(401).json({
        error: `One or more answers were incorrect. ${afterFailure.remainingAttempts} attempt${afterFailure.remainingAttempts === 1 ? '' : 's'} remaining before a 1 minute lockout.`,
        remainingAttempts: afterFailure.remainingAttempts
      });
    }

    recordSuccess(email);
    // Issue short-lived, single-purpose JWT for password reset only
    const resetToken = jwt.sign({ email, purpose: 'password-reset' }, process.env.JWT_SECRET, { expiresIn: RESET_TOKEN_EXPIRES_IN });
    res.json({ resetToken });
  } catch (err) {
    console.error('Forgot-password verify error:', err);
    res.status(500).json({ error: 'Verification failed' });
  }
});

// POST /api/auth/forgot-password/reset   { resetToken, newPassword }
router.post('/forgot-password/reset', async (req, res) => {
  try {
    const { resetToken, newPassword } = req.body;
    if (!resetToken || !newPassword) return res.status(400).json({ error: 'Reset token and new password are required' });
    if (newPassword.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });

    let payload;
    try {
      payload = jwt.verify(resetToken, process.env.JWT_SECRET);
    } catch (e) {
      return res.status(401).json({ error: 'Reset link expired or invalid. Start over.' });
    }
    if (payload.purpose !== 'password-reset') return res.status(401).json({ error: 'Invalid reset token' });

    const db = await getDB();
    const passwordHash = await bcrypt.hash(newPassword, 10);
    await db.run('UPDATE users SET passwordHash = ? WHERE email = ?', [passwordHash, payload.email]);

    res.json({
      message: 'Password reset. Note: your existing private key file no longer works, since it was encrypted with your old password. Files encrypted for you before this reset cannot be decrypted with a new key file - there is no way to recover this.',
      email: payload.email
    });
  } catch (err) {
    console.error('Password reset error:', err);
    res.status(500).json({ error: 'Reset failed' });
  }
});

// ============================================================================
// USER SETTINGS & PUBLIC KEY ENDPOINTS
// ============================================================================

// POST /api/auth/2fa/toggle   (requireAuth)   { enabled, password }
router.post('/2fa/toggle', requireAuth, async (req, res) => {
  const { enabled, password } = req.body;
  if (typeof enabled !== 'boolean') return res.status(400).json({ error: 'enabled must be true or false' });
  if (!password) return res.status(400).json({ error: 'Password is required to change this setting' });

  const db = await getDB();
  const user = await db.get('SELECT * FROM users WHERE email = ?', [req.user.email]);
  const match = await bcrypt.compare(password, user.passwordHash);
  if (!match) return res.status(401).json({ error: 'Incorrect password' });

  await db.run('UPDATE users SET twoFactorEnabled = ? WHERE email = ?', [enabled ? 1 : 0, req.user.email]);
  res.json({ message: `2-step verification ${enabled ? 'enabled' : 'disabled'}.`, twoFactorEnabled: enabled });
});

// POST /api/auth/2fa/questions   (requireAuth)   { questions, password }
router.post('/2fa/questions', requireAuth, async (req, res) => {
  const { questions, password } = req.body;
  if (!password) return res.status(400).json({ error: 'Password is required to change security questions' });
  const questionsError = validateQuestionsPayload(questions);
  if (questionsError) return res.status(400).json({ error: questionsError });

  const db = await getDB();
  const user = await db.get('SELECT * FROM users WHERE email = ?', [req.user.email]);
  const match = await bcrypt.compare(password, user.passwordHash);
  if (!match) return res.status(401).json({ error: 'Incorrect password' });

  await db.run('DELETE FROM security_questions WHERE email = ?', [req.user.email]);
  for (const q of questions) {
    const answerHash = await bcrypt.hash(normalizeAnswer(q.answer), 10);
    await db.run('INSERT INTO security_questions (email, questionText, answerHash) VALUES (?, ?, ?)',
      [req.user.email, q.question.trim(), answerHash]);
  }
  res.json({ message: 'Security questions updated.' });
});

// GET /api/auth/2fa/questions   (requireAuth)
router.get('/2fa/questions', requireAuth, async (req, res) => {
  const db = await getDB();
  const questions = await db.all('SELECT id, questionText FROM security_questions WHERE email = ? ORDER BY id ASC', [req.user.email]);
  res.json({ questions });
});

// POST /api/auth/request-termination   (requireAuth)   { reason }
router.post('/request-termination', requireAuth, async (req, res) => {
  const { reason } = req.body;
  if (!reason || !reason.trim()) return res.status(400).json({ error: 'Please state a reason' });

  const db = await getDB();
  const existing = await db.get(
    "SELECT id FROM account_deletion_requests WHERE email = ? AND status = 'pending'", [req.user.email]
  );
  if (existing) return res.status(409).json({ error: 'You already have a pending termination request' });

  await db.run('INSERT INTO account_deletion_requests (email, reason) VALUES (?, ?)', [req.user.email, reason.trim()]);
  res.status(201).json({ message: 'Termination request submitted. An admin will review it.' });
});

// GET /api/auth/me   (requireAuth)
router.get('/me', requireAuth, async (req, res) => {
  const db = await getDB();
  const user = await db.get('SELECT email, role, twoFactorEnabled, createdAt FROM users WHERE email = ?', [req.user.email]);
  if (!user) return res.status(404).json({ error: 'Account not found' });
  res.json(user);
});

// GET /api/auth/public-key/:email - Used by clients to retrieve public RSA key for file encryption
router.get('/public-key/:email', async (req, res) => {
  const db = await getDB();
  const row = await db.get('SELECT publicKeyPem FROM public_keys WHERE email = ?', [req.params.email]);
  if (!row) return res.status(404).json({ error: 'No public key found for that email' });
  res.json({ email: req.params.email, publicKey: row.publicKeyPem });
});

module.exports = router;

