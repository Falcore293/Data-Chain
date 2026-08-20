// ============================================================================
// db/database.js — Database Initialization & Security Schema
// ============================================================================
//
// WHAT IS THIS FILE?
// ------------------
// This file initializes the SQLite relational database (`datachain.db`) and defines
// all security-critical table schemas used across the application.
//
// CORE SECURITY ARCHITECTURE CONCEPTS:
// ------------------------------------
//  1. Zero-Knowledge Private Key Storage:
//     - The server NEVER stores private RSA keys, encrypted or otherwise.
//     - Upon signup, private keys are generated, encrypted client-side/in-memory,
//       downloaded by the user, and immediately purged from server memory.
//     - If the user loses their key file, server admins CANNOT recover it.
//
//  2. Password & Answer Hashing (bcrypt):
//     - Plaintext passwords and security question answers are NEVER saved to disk.
//     - Instead, cryptographic salt hashes (bcrypt) are stored.
//     - Attainable DB leak will not reveal actual passwords or security answers.
//
//  3. Relational Integrity & Cascading Deletes:
//     - SQLite foreign keys are explicitly enabled (`PRAGMA foreign_keys = ON;`).
//     - Account deletion cascades down to wipe user public keys, files, and memberships.
//
//  4. Comprehensive Audit Trails & Log Separation:
//     - `transactions`: Immutable, hash-chained ledger for data operations.
//     - `login_logs`: Tracks all authentication attempts (success & failure + IP).
//     - `access_logs`: Tracks access attempts (view, download, denied).
//     - `security_events`: Tracks security anomalies (e.g. account lockouts).
// ============================================================================

// db/database.js
// Opens (or creates) the SQLite database file and makes sure every table
// Data Chain needs exists. Called once when the server boots.

const sqlite3 = require('sqlite3').verbose();
const { open } = require('sqlite');
const path = require('path');

const DB_PATH = path.join(__dirname, '..', 'datachain.db');

let dbInstance = null;

async function getDB() {
  if (dbInstance) return dbInstance;

  // Connect to or create the SQLite database file
  dbInstance = await open({
    filename: DB_PATH,
    driver: sqlite3.Database
  });

  // Foreign keys are off by default in SQLite - explicitly turn them ON
  // to enforce referential integrity across relational tables.
  await dbInstance.exec('PRAGMA foreign_keys = ON;');

  await dbInstance.exec(`
    -- Core user account table.
    -- SECURITY DESIGN: No private key column exists here on purpose.
    -- The private key is generated at signup, handed to the user as a file download,
    -- and never stored server-side.
    CREATE TABLE IF NOT EXISTS users (
      id                INTEGER PRIMARY KEY AUTOINCREMENT,
      email             TEXT UNIQUE NOT NULL,
      passwordHash      TEXT NOT NULL,                  -- bcrypt hash of user password
      role              TEXT NOT NULL DEFAULT 'user',   -- Role-Based Access Control: 'user' | 'admin'
      twoFactorEnabled  INTEGER NOT NULL DEFAULT 0,     -- 2-Step Verification toggle
      suspended         INTEGER NOT NULL DEFAULT 0,     -- Emergency admin suspension switch
      createdAt         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
    );

    -- Security questions table used for 2-step verification & password resets.
    -- SECURITY DESIGN: Answers are hashed with bcrypt, never stored in plaintext.
    CREATE TABLE IF NOT EXISTS security_questions (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      email         TEXT NOT NULL,
      questionText  TEXT NOT NULL,
      answerHash    TEXT NOT NULL,                      -- bcrypt hash of normalized answer
      createdAt     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
      FOREIGN KEY (email) REFERENCES users(email) ON DELETE CASCADE
    );

    -- Authentication Audit Log: Records every login attempt (success/failure)
    -- along with IP addresses for threat monitoring and CSV exports.
    CREATE TABLE IF NOT EXISTS login_logs (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      email       TEXT NOT NULL,
      success     INTEGER NOT NULL,                     -- 1 = Success, 0 = Failure
      detail      TEXT,                                 -- Reason or mode (e.g. 'wrong password')
      ipAddress   TEXT,                                 -- Source IP address of requester
      timestamp   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
    );

    -- Security Anomaly Log: Triggered when accounts hit brute-force lockouts.
    -- Used by the Admin "Security Alerts" panel to spot active attacks.
    CREATE TABLE IF NOT EXISTS security_events (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      email       TEXT NOT NULL,
      eventType   TEXT NOT NULL,                       -- e.g. 'lockout'
      detail      TEXT,                                 -- e.g. '3 failed attempts'
      timestamp   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
    );

    -- Public Keys Directory: Stores RSA public keys.
    -- Public keys are non-sensitive and required so other users can encrypt files for them.
    CREATE TABLE IF NOT EXISTS public_keys (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      email         TEXT UNIQUE NOT NULL,
      publicKeyPem  TEXT NOT NULL,                      -- Standard RSA Public Key in PEM format
      createdAt     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
      FOREIGN KEY (email) REFERENCES users(email) ON DELETE CASCADE
    );

    -- Shared Group Folders: Defines team spaces for secure group file sharing.
    CREATE TABLE IF NOT EXISTS groups (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      name          TEXT NOT NULL,
      ownerEmail    TEXT NOT NULL,                      -- Group creator/administrator
      createdAt     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
      FOREIGN KEY (ownerEmail) REFERENCES users(email) ON DELETE CASCADE
    );

    -- Group Membership Table: Maps users to groups for access control.
    CREATE TABLE IF NOT EXISTS group_members (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      groupId       INTEGER NOT NULL,
      memberEmail   TEXT NOT NULL,
      addedBy       TEXT NOT NULL,
      joinedAt      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
      UNIQUE(groupId, memberEmail),
      FOREIGN KEY (groupId) REFERENCES groups(id) ON DELETE CASCADE,
      FOREIGN KEY (memberEmail) REFERENCES users(email) ON DELETE CASCADE
    );

    -- File Metadata Table: Represents a file entity and its access parameters.
    -- Holds time-based access control rules (expiryType, expiresAt).
    CREATE TABLE IF NOT EXISTS files (
      id              INTEGER PRIMARY KEY AUTOINCREMENT,
      originalName    TEXT NOT NULL,                    -- Display filename
      ownerEmail      TEXT NOT NULL,                    -- Uploader / Owner
      receiverEmail   TEXT,                             -- NULL for personal/group, populated for 1:1 sends
      groupId         INTEGER,                          -- NULL for personal/1:1, populated for group shares
      expiryType      TEXT DEFAULT 'none',              -- none | 1h | 1d | 3d | custom
      expiresAt       TEXT,                             -- Expiration ISO timestamp (NULL = permanent)
      downloadCount   INTEGER NOT NULL DEFAULT 0,       -- Tracks download frequency
      isExpired       INTEGER NOT NULL DEFAULT 0,       -- Expiry status flag
      createdAt       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
      FOREIGN KEY (ownerEmail) REFERENCES users(email) ON DELETE CASCADE,
      FOREIGN KEY (groupId) REFERENCES groups(id) ON DELETE CASCADE
    );

    -- File Versions Table: Stores encrypted file metadata for each version.
    -- Implements envelope encryption parameters (IV, AuthTag, AES Key).
    CREATE TABLE IF NOT EXISTS file_versions (
      id              INTEGER PRIMARY KEY AUTOINCREMENT,
      fileId          INTEGER NOT NULL,                 -- Links to parent files.id
      versionNumber   INTEGER NOT NULL,                 -- Version sequence number (1, 2, 3...)
      storedName      TEXT NOT NULL,                    -- Randomized UUID filename on disk
      fileHash        TEXT NOT NULL,                    -- SHA-256 hash of original file content
      fileSize        INTEGER NOT NULL,                 -- Size in bytes
      iv              TEXT NOT NULL,                    -- AES-256-GCM Initialization Vector
      authTag         TEXT NOT NULL,                    -- AES-256-GCM Authentication Tag for integrity
      encryptedKey    TEXT,                             -- Single recipient's RSA-wrapped AES key (NULL for groups)
      uploadedBy      TEXT NOT NULL,
      createdAt       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
      FOREIGN KEY (fileId) REFERENCES files(id) ON DELETE CASCADE
    );

    -- Multi-Recipient Group Encryption Keys:
    -- Stores individual RSA-wrapped AES keys for every group member per file version.
    CREATE TABLE IF NOT EXISTS version_keys (
      id              INTEGER PRIMARY KEY AUTOINCREMENT,
      versionId       INTEGER NOT NULL,
      recipientEmail  TEXT NOT NULL,
      encryptedKey    TEXT NOT NULL,                    -- RSA-wrapped AES key specific to recipient's public key
      UNIQUE(versionId, recipientEmail),
      FOREIGN KEY (versionId) REFERENCES file_versions(id) ON DELETE CASCADE
    );

    -- Hash-Chained Blockchain Ledger Table:
    -- Provides an immutable audit trail. Each block stores the hash of the previous block.
    CREATE TABLE IF NOT EXISTS transactions (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      blockIndex    INTEGER NOT NULL,                   -- Sequenced index starting at 0
      action        TEXT NOT NULL,                      -- Action type (upload, send, download, etc.)
      sender        TEXT NOT NULL,                      -- Initiator email
      receiver      TEXT,                               -- Target recipient / group tag
      fileHash      TEXT NOT NULL,                      -- SHA-256 content hash
      timestamp     TEXT NOT NULL,                      -- Immutable timestamp
      previousHash  TEXT NOT NULL,                      -- Hash of previous block (Chaining link)
      blockHash     TEXT NOT NULL                       -- Hash of current block content + previousHash
    );

    -- File Access Audit Log:
    -- Records all file interaction attempts (views, downloads, and denied access).
    CREATE TABLE IF NOT EXISTS access_logs (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      fileId      INTEGER,
      userEmail   TEXT NOT NULL,
      action      TEXT NOT NULL,                        -- view | download | denied
      detail      TEXT,                                 -- Contextual details (e.g. 'expired', 'denied')
      timestamp   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
      FOREIGN KEY (fileId) REFERENCES files(id) ON DELETE CASCADE
    );

    -- Self-Service Account Termination Requests Table:
    -- User-submitted requests for account deletion, requiring admin review.
    CREATE TABLE IF NOT EXISTS account_deletion_requests (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      email         TEXT NOT NULL,
      reason        TEXT NOT NULL,
      status        TEXT NOT NULL DEFAULT 'pending',     -- pending | approved | rejected
      requestedAt   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
      resolvedAt    TEXT,
      resolvedBy    TEXT
    );
  `);

  return dbInstance;
}

module.exports = { getDB };

