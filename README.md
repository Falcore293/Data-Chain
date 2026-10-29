# Data Chain — Settings Consolidation, Password Reset, Admin Oversight, Timestamp Fix

## What's new

### 1. Settings replaces Security
One panel now covers: KBA (Knowledge-Based Authentication) verification toggle, changing security
questions, and requesting account termination. The old "Security"
enable/disable flow is gone.

### 2. Password reset via security questions
New unauthenticated flow at `forgot-password.html` (linked from the
login page): enter email → answer your 2 security questions → set a
new password. Shares the same 3-strikes/1-minute lockout as normal
login, since it's the same account being protected either way.

**Read this before using it**: your login password also derives the
key that decrypts your private key file. Resetting your password does
**not** re-encrypt your existing key file — it can't, since the server
never has the plaintext key to begin with. After a reset, your old
`.datachain-key.json` stops working, permanently. The reset page shows
this warning before you can submit. This is a real, unavoidable
consequence of never storing the key server-side, not a bug.

### 3. Account termination requests
Settings → state a reason → submitted to admins as `pending`. Nothing
is deleted until an admin approves it from the new Admin → **Account
Requests** tab. Approving actually deletes the account (cascades to
their files, group memberships, etc. via foreign keys) — there's a
confirm dialog since it's irreversible.

### 4. Security questions now mandatory at signup
Two questions + answers are required to create an account (this is
what makes #2 possible for every account). Whether they're **also**
asked at login is a separate toggle in Settings, off by default — you
can turn it on/off any time without losing the questions themselves.

### 5. Admin: Account Requests
See item 3.

### 6. Admin: Online Now
Live list of who's currently connected, via Socket.IO presence
tracking (`utils/presence.js`). Updates in real time as people log
in/out — no page refresh needed while the tab is open.

### 7. Admin: File Traffic + Suspend (the honest version of "force stop")
A live feed of every upload/send/download/version/group-share as it
happens. **On force-stopping an in-progress transfer**: uploads here
are small, synchronous, memory-buffered operations — there's no
long-running stream to grab onto mid-flight the way you'd interrupt a
video call. What actually works and is built: **Suspend** a user from
the Users tab — it blocks that account's file operations (upload,
send, version, download) starting with their *very next request*,
checked fresh against the DB every time rather than baked into their
session token. If you spot something anomalous in the traffic feed,
suspend the account right then.

### 8. Timestamp bug — fixed
Root cause: SQLite's `datetime('now')` produces a format like
`2026-08-12 04:16:41` with no timezone marker. Browsers parsing that
string (via `new Date(...)`) interpret it as **local** time instead of
UTC, which silently shifted every displayed timestamp by your
timezone offset. Fixed by switching every table's default to
`strftime('%Y-%m-%dT%H:%M:%fZ','now')`, which produces real ISO 8601
(`...T...Z`) that every JS engine parses correctly as UTC before
converting to the viewer's local time for display.

**This requires deleting `datachain.db` again** — SQLite bakes a
column's DEFAULT expression in at `CREATE TABLE` time, so existing
tables keep the old (buggy) default even after this file changes.

## Setup

```bash
cd data-chain
npm install
rm -f datachain.db   # required this time - see timestamp fix above
npm start
```

Set `ADMIN_EMAIL` in `.env` before signing up with that email for an
admin account.

## Try it
1. Sign up — notice the 2 security questions are now required.
2. Log out. On the login page, click "Forgot your password?" → answer
   your questions → reset → read the warning carefully.
3. As admin: **Admin → Online Now** — open a second browser/incognito,
   log in as someone else, watch them appear live.
4. As admin: **Admin → File Traffic** — upload a file in the other
   session, watch it appear at the top of the feed without refreshing.
5. As admin: **Admin → Users** → Suspend a non-admin account → try
   uploading as that user → blocked immediately.
6. As a user: **Settings** → submit a termination request → as admin,
   **Admin → Account Requests** → Approve or Reject.
7. Check any timestamp in Admin → Logs against your system clock — it
   should now match (after deleting the old `datachain.db`).

## Project structure
```
data-chain/
├── server.js                    # + presence tracking, admin-room
├── db/database.js               # + suspended, account_deletion_requests, ISO timestamps
├── utils/
│   ├── crypto.js / blockchain.js / expiry.js / loginAttempts.js
│   └── presence.js              # NEW: online tracking
├── middleware/auth.js           # + requireNotSuspended
├── routes/
│   ├── auth.js                  # mandatory signup questions, toggle-KBA, forgot-password, termination request
│   ├── files.js / groups.js     # + suspension checks, traffic broadcast
│   ├── blockchain.js
│   └── admin.js                 # + suspend, deletion requests, online users, file traffic
└── public/
    ├── login.html                # + forgot password link
    ├── signup.html                # + mandatory security questions
    ├── forgot-password.html      # NEW: 3-step reset flow
    ├── dashboard.html             # Settings replaces Security; Admin gets 3 new tabs
    └── js/
        ├── login.js / signup.js / forgot-password.js
        ├── dashboard.js           # + shared socket, admin room join, suspension handling
        ├── settings.js            # NEW: replaces security.js
        └── admin.js                # + requests/online/traffic tabs, suspend button
```
