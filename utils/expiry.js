// ============================================================================
// utils/expiry.js — Time-Based Access Control (File Expiry)
// ============================================================================
//
// WHAT IS THIS FILE?
// ------------------
// This module handles file access expiration — the ability for a file owner
// to set a time limit on how long a file can be accessed. After the time
// window closes, the file becomes inaccessible (though it's NOT deleted —
// it just can't be downloaded anymore).
//
// SECURITY CONCEPT: Time-Based Access Control
// -------------------------------------------
// Time-based access control limits HOW LONG someone can access a resource.
// This is useful for sensitive files that should only be available
// temporarily — for example, a contract that should only be downloadable
// for 24 hours after it's sent.
//
// AVAILABLE EXPIRY OPTIONS:
//   • 'none' — no expiry, accessible forever (default)
//   • '1h'   — accessible for 1 hour from when the setting is applied
//   • '1d'   — accessible for 1 day (24 hours)
//   • '3d'   — accessible for 3 days (72 hours)
//   • 'custom' — a custom number of hours specified by the user
//
// HOW IT WORKS:
//   1. When a file is uploaded/sent, the owner can choose an expiry type
//   2. computeExpiry() converts that type into a concrete timestamp
//      (e.g., "2024-01-15T14:30:00Z")
//   3. That timestamp is stored in the database alongside the file
//   4. On every download attempt, isFileExpired() checks the current time
//      against the stored timestamp
//   5. If the current time is past the expiry, the download is denied
// ============================================================================

// utils/expiry.js
// Time-based access control: the ONLY access rule left in Data Chain.
// Turns a duration choice into a concrete expiresAt timestamp.

// Constant for one hour in milliseconds.
// Used as the base unit for all expiry calculations.
// 60 seconds × 60 minutes × 1000 milliseconds = 3,600,000 ms
const HOUR = 60 * 60 * 1000;

// ============================================================================
// computeExpiry — Converts an Expiry Type into a Concrete Timestamp
// ============================================================================
// PURPOSE:
//   Takes a human-friendly expiry choice (like '1h' or '3d') and calculates
//   the exact date/time when the file should expire.
//
// EXAMPLE:
//   If it's currently 2:00 PM and the user chooses '1h':
//   → expiresAt = "2024-01-15T15:00:00.000Z" (3:00 PM, one hour later)
//
// RETURNS:
//   { expiresAt: "ISO-8601 timestamp" } or { expiresAt: null } for no expiry
// ============================================================================
function computeExpiry(expiryType, customHours) {
  // Get the current time in milliseconds since Jan 1, 1970 (Unix epoch).
  const now = Date.now();

  switch (expiryType) {
    // Preset durations: add the appropriate number of milliseconds to "now"
    // and convert to an ISO 8601 timestamp string.
    case '1h':
      return { expiresAt: new Date(now + 1 * HOUR).toISOString() };
    case '1d':
      return { expiresAt: new Date(now + 24 * HOUR).toISOString() };
    case '3d':
      return { expiresAt: new Date(now + 72 * HOUR).toISOString() };

    // Custom duration: the user specifies how many hours.
    // We validate that it's a positive number to prevent invalid expiry times.
    case 'custom': {
      const hours = Number(customHours);
      if (!hours || hours <= 0) {
        throw new Error('Custom access duration must be a positive number of hours');
      }
      return { expiresAt: new Date(now + hours * HOUR).toISOString() };
    }

    // No expiry: the file is accessible forever. expiresAt = null means
    // "never expires" — the download route checks for this and skips
    // the expiry check entirely.
    case 'none':
    default:
      return { expiresAt: null };
  }
}

// ============================================================================
// isFileExpired — Checks Whether a File's Access Window Has Closed
// ============================================================================
// PURPOSE:
//   Called on every download attempt to determine if the file can still
//   be accessed. Returns true if the file is expired, false if still valid.
//
// TWO WAYS A FILE CAN BE EXPIRED:
//   1. The isExpired flag is already set to true in the database (an admin
//      or the system already marked it as expired)
//   2. The current time is past the expiresAt timestamp (the time-based
//      window has closed)
//
// If expiresAt is null, the file never expires (expiryType = 'none').
// ============================================================================

// Checks a file row against "now" and returns whether it's still accessible.
function isFileExpired(fileRow) {
  // Check 1: Has the file already been flagged as expired?
  if (fileRow.isExpired) return true;

  // Check 2: Has the expiry timestamp passed?
  // If expiresAt exists and the current time is past it, the file is expired.
  if (fileRow.expiresAt && new Date(fileRow.expiresAt).getTime() < Date.now()) return true;

  // Neither condition met — the file is still accessible.
  return false;
}

// Export both functions for use in routes/files.js:
//   computeExpiry   → called when setting/updating file access duration
//   isFileExpired   → called on every download attempt to check access
module.exports = { computeExpiry, isFileExpired };
