// ============================================================================
// utils/loginAttempts.js — Brute-Force Protection (Account Lockout)
// ============================================================================
//
// WHAT IS THIS FILE?
// ------------------
// This module tracks failed login attempts per email address and temporarily
// locks accounts after too many wrong guesses. This is a critical defense
// against BRUTE-FORCE ATTACKS — where an attacker tries thousands of
// passwords hoping to guess the right one.
//
// SECURITY CONCEPT: Account Lockout
// ----------------------------------
// Without lockout, an attacker could try unlimited passwords at high speed.
// Even a strong password could eventually be guessed given enough attempts.
// With lockout:
//   - After 3 wrong password attempts → account is locked for 1 minute
//   - During lockout, ALL login attempts are rejected immediately
//   - After the cooldown, the user gets 3 fresh attempts
//
// This makes brute-force attacks impractically slow. An attacker can only
// try 3 passwords per minute (180 per hour), compared to potentially
// millions per second without protection.
//
// HOW IT WORKS WITH RATE LIMITING:
// --------------------------------
// This module protects individual ACCOUNTS (tracked by email). The rate
// limiter in server.js protects the ENDPOINT (tracked by IP address).
// Together, they defend against two different attack strategies:
//   - Same IP, different accounts → rate limiter catches it
//   - Different IPs, same account → account lockout catches it
//
// IN-MEMORY STORAGE NOTE:
// -----------------------
// Attempt counts are stored in a JavaScript Map (RAM), not in the database.
// This means they reset if the server restarts. For a production system,
// you'd use Redis or a database table so lockouts survive restarts and
// work across multiple server instances. For this project (single process),
// in-memory storage is sufficient and faster.
// ============================================================================

// utils/loginAttempts.js
// Tracks failed login attempts PER EMAIL so a wrong password can't just
// be retried forever - 3 tries, then a 1 minute cooldown. In-memory is
// fine for an FYP demo running as a single process; a real deployment
// would move this to Redis or a DB table so it survives a restart and
// works across multiple server instances.

// Maximum number of failed attempts before lockout.
// 3 is a common industry standard — it balances security (limiting guesses)
// with usability (legitimate users occasionally mistype passwords).
const MAX_ATTEMPTS = 3;

// Lockout duration in milliseconds.
// 1 minute = 60 seconds × 1000 milliseconds.
// Short enough to not severely inconvenience legitimate users who mistyped
// their password, but long enough to make brute-force attacks very slow.
const LOCKOUT_MS = 60 * 1000; // 1 minute

// In-memory storage: Maps each email to its attempt tracking object.
// Structure: email → { count: number, lockedUntil: timestamp|null }
//   - count: how many failed attempts since the last reset
//   - lockedUntil: Unix timestamp when the lockout expires (null if not locked)
const attempts = new Map(); // email -> { count, lockedUntil }

// ============================================================================
// getStatus — Check Whether an Account is Currently Locked
// ============================================================================
// PURPOSE:
//   Called BEFORE processing a login attempt to check if the account is
//   currently locked out. Also reports how many attempts remain.
//
// RETURNS one of:
//   { locked: true, remainingMs: N }  → account is locked, wait N ms
//   { locked: false, remainingAttempts: N } → account is open, N tries left
// ============================================================================
function getStatus(email) {
  const entry = attempts.get(email);

  // No record for this email → clean slate, all attempts available.
  if (!entry) return { locked: false, remainingAttempts: MAX_ATTEMPTS };

  // Check if there's an active lockout that hasn't expired yet.
  if (entry.lockedUntil && Date.now() < entry.lockedUntil) {
    // Account is locked — tell the caller how many milliseconds remain.
    return { locked: true, remainingMs: entry.lockedUntil - Date.now() };
  }

  // Lock has expired (or there wasn't one yet) - attempts still count
  // until a successful login clears them, but no active lock right now.
  if (entry.lockedUntil && Date.now() >= entry.lockedUntil) {
    // Cooldown has passed — give the user a completely fresh start.
    attempts.delete(email); // cooldown passed, give them a clean slate
    return { locked: false, remainingAttempts: MAX_ATTEMPTS };
  }

  // Not locked, but some attempts have been used — report how many remain.
  return { locked: false, remainingAttempts: MAX_ATTEMPTS - entry.count };
}

// ============================================================================
// recordFailure — Register a Failed Login Attempt
// ============================================================================
// PURPOSE:
//   Called when a login attempt fails (wrong password or wrong security
//   question answers). Increments the failure counter and triggers lockout
//   if the limit is reached.
//
// LOCKOUT TRIGGER:
//   When count reaches MAX_ATTEMPTS (3), the account is locked by setting
//   lockedUntil to the current time + LOCKOUT_MS (1 minute from now).
//   The count is then reset to 0 so the NEXT lockout window also gets
//   3 fresh attempts.
//
// SHARED BUCKET:
//   The same lockout counter is shared between login, 2FA verification,
//   and password reset attempts. This prevents attackers from bypassing
//   the login lockout by switching to the password reset flow.
// ============================================================================
function recordFailure(email) {
  // Get existing record or create a new one with 0 failures.
  const entry = attempts.get(email) || { count: 0, lockedUntil: null };

  // Increment the failure count.
  entry.count += 1;

  // If we've hit the maximum, trigger the lockout.
  if (entry.count >= MAX_ATTEMPTS) {
    entry.lockedUntil = Date.now() + LOCKOUT_MS;  // Lock for 1 minute
    entry.count = 0; // reset so the next window is also 3 tries
  }

  // Save the updated record.
  attempts.set(email, entry);

  // Return the current status so the caller can include it in the response
  // (e.g., "2 attempts remaining before a 1 minute lockout").
  return getStatus(email);
}

// ============================================================================
// recordSuccess — Clear All Lockout State After a Successful Login
// ============================================================================
// PURPOSE:
//   Called when a login succeeds. Completely removes the email from the
//   tracking map, giving the user a clean slate. This ensures that a few
//   typos followed by a correct password don't carry over failed attempts
//   into the next login session.
// ============================================================================
function recordSuccess(email) {
  attempts.delete(email);
}

// Export all functions and constants:
//   - getStatus      → check if an account is locked before attempting login
//   - recordFailure  → register a failed attempt (may trigger lockout)
//   - recordSuccess  → clear lockout state after successful login
//   - MAX_ATTEMPTS   → the threshold (3) — used in error messages
//   - LOCKOUT_MS     → the duration (60000ms) — used in error messages
module.exports = { getStatus, recordFailure, recordSuccess, MAX_ATTEMPTS, LOCKOUT_MS };
