// ============================================================================
// utils/presence.js — Real-Time User Presence Tracker
// ============================================================================
//
// WHAT IS THIS FILE?
// ------------------
// This utility tracks which users are currently online (connected via Socket.IO
// WebSockets). It powers the "Online Users" widget in the admin dashboard.
//
// HOW IT WORKS:
// -------------
//  • Maintains two bidirectional maps in memory (RAM):
//    1. socketToEmail: Maps a socket ID (browser connection) -> user email.
//    2. emailToSockets: Maps a user email -> Set of socket IDs.
//       (A user can open multiple tabs/devices, so 1 email can have N sockets).
//
// SECURITY & PRIVACY CONSIDERATIONS:
// ----------------------------------
//  • Presence information allows administrators to see active user status in
//    real-time, aiding monitoring and incident detection (e.g. noticing unusual
//    active accounts during an incident).
//  • Stored entirely in-memory: presence automatically resets on server restart,
//    preventing "stale" online status logs from persisting.
// ============================================================================

// utils/presence.js
// Tracks who's currently connected via Socket.IO, so the admin panel
// can show "online right now". In-memory only - fine for a single
// process; resets on server restart, same caveat as loginAttempts.js.

// Fast O(1) key-value lookup maps:
const socketToEmail = new Map(); // socketId -> email
const emailToSockets = new Map(); // email -> Set of socketIds (multiple tabs/devices)

/**
 * Marks a socket connection as associated with a specific user email.
 * Handles multiple simultaneous device/tab connections for the same user.
 */
function markOnline(socketId, email) {
  socketToEmail.set(socketId, email);
  if (!emailToSockets.has(email)) emailToSockets.set(email, new Set());
  emailToSockets.get(email).add(socketId);
}

/**
 * Removes a socket connection when a user disconnects or closes a tab.
 * If all tabs for a user are closed, the user is considered offline.
 */
function markOffline(socketId) {
  const email = socketToEmail.get(socketId);
  if (!email) return;
  socketToEmail.delete(socketId);
  const sockets = emailToSockets.get(email);
  if (sockets) {
    sockets.delete(socketId);
    // If no remaining active sockets/tabs, remove user from online map
    if (sockets.size === 0) emailToSockets.delete(email);
  }
}

/**
 * Returns a list of all currently active user email addresses.
 */
function listOnline() {
  return [...emailToSockets.keys()];
}

/**
 * Checks if a specific user email is currently online.
 */
function isOnline(email) {
  return emailToSockets.has(email);
}

module.exports = { markOnline, markOffline, listOnline, isOnline };

