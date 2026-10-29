// ============================================================================
// server.js — Application Entry Point (Main Server File)
// ============================================================================
//
// WHAT IS THIS FILE?
// ------------------
// This is the starting point of the entire Data Chain application. When you
// run "npm start" or "node server.js", THIS is the file that runs. It:
//   1. Loads configuration from the .env file
//   2. Sets up security middleware (protective layers)
//   3. Connects all the API routes (auth, files, blockchain, groups, admin)
//   4. Starts Socket.IO for real-time notifications
//   5. Opens the database and starts listening for web requests
//
// SECURITY CONCEPTS IN THIS FILE:
// --------------------------------
//  • Defense in Depth — multiple layers of protection (Helmet, CORS, rate
//    limiting) rather than relying on a single security measure.
//  • Rate Limiting — prevents brute-force attacks by limiting how many
//    login/signup attempts a single IP can make in a time window.
//  • HTTP Security Headers — Helmet automatically sets headers like
//    X-Content-Type-Options, X-Frame-Options, etc., to prevent common
//    web attacks (clickjacking, MIME-type sniffing, etc.).
// ============================================================================

// server.js

// Load environment variables from the .env file (e.g., JWT_SECRET, PORT,
// ADMIN_EMAIL). These are sensitive configuration values that should NEVER
// be hard-coded in source code — storing them in .env keeps secrets out
// of version control (Git).
require('dotenv').config();

// --- IMPORTS ---

// Express: the web framework that handles HTTP requests and responses.
// Think of it as the "receptionist" that routes incoming requests to the
// right handler function.
const express = require('express');

// CORS (Cross-Origin Resource Sharing): controls which websites/domains
// are allowed to make requests to this server. Without CORS, a browser
// would block requests from a different domain for security reasons
// (called the "Same-Origin Policy"). Here it's set to allow all origins
// for development convenience.
const cors = require('cors');

// Helmet: automatically sets various HTTP security headers on every
// response. These headers tell the browser to enable built-in security
// features like preventing clickjacking (X-Frame-Options), blocking
// MIME-type sniffing (X-Content-Type-Options), and more. It's like
// putting a helmet on your server — simple but effective protection.
const helmet = require('helmet');

// Morgan: logs every incoming HTTP request to the console (method, URL,
// status code, response time). Useful for debugging and monitoring —
// you can see exactly what's happening on the server in real time.
const morgan = require('morgan');

// express-rate-limit: limits how many requests a single IP address can
// make to specific endpoints within a time window. This is a defense
// against brute-force attacks — if someone tries to guess passwords by
// rapidly sending login requests, they'll be temporarily blocked after
// hitting the limit.
const rateLimit = require('express-rate-limit');

// path: Node.js built-in module for working with file and directory
// paths in a cross-platform way (Windows vs Linux use different
// path separators: \ vs /).
const path = require('path');

// http: Node.js built-in module. We need a raw HTTP server (not just
// Express) because Socket.IO needs to attach to it for WebSocket
// support (real-time, two-way communication).
const http = require('http');

// Socket.IO: enables real-time, bidirectional communication between
// the server and connected browsers. Unlike normal HTTP (where the
// browser asks and the server answers), Socket.IO lets the server
// PUSH updates to the browser instantly — used here for live
// notifications like "you received a file" and admin dashboard
// real-time feeds.
const { Server } = require('socket.io');

// --- APPLICATION MODULE IMPORTS ---

// Database connection manager — returns the SQLite database instance.
const { getDB } = require('./db/database');

// Route modules — each handles a group of related API endpoints:
const authRoutes = require('./routes/auth');           // signup, login, KBA, password reset
const filesRoutes = require('./routes/files');         // upload, send, download, versioning
const blockchainRoutes = require('./routes/blockchain'); // view & validate the hash-chained ledger
const groupsRoutes = require('./routes/groups');       // create groups, add members, group file sharing
const adminRoutes = require('./routes/admin');         // admin dashboard: users, logs, alerts, suspension

// Presence tracker — keeps an in-memory record of which users are
// currently connected via Socket.IO (for the admin "online users" panel).
const presence = require('./utils/presence');

// --- CREATE THE SERVER ---

// Create an Express application instance.
const app = express();

// Wrap it in a raw HTTP server so Socket.IO can attach to it.
const server = http.createServer(app);

// Create a Socket.IO server instance attached to the HTTP server.
const io = new Server(server);

// ============================================================================
// MIDDLEWARE STACK
// ============================================================================
// Middleware functions run IN ORDER on every incoming request BEFORE it
// reaches the actual route handler. Think of them as a series of security
// checkpoints at an airport — each one inspects or modifies the request
// before letting it through to the next.
// ============================================================================

// --- Core middleware ---

// Helmet sets ~15 HTTP security headers automatically. We disable the
// Content-Security-Policy (CSP) header for now because the frontend loads
// a third-party script (forge.js) from a CDN, and a strict CSP would block
// it. In a production deployment, you'd configure a proper CSP whitelist
// instead of disabling it entirely.
app.use(helmet({
  contentSecurityPolicy: false // relaxed for now so CDN scripts (forge.js) can load; tighten before production
}));

// Enable CORS so the frontend (which may be served from a different port
// during development) can make API requests to this server.
app.use(cors());

// Log every request to the console in a developer-friendly format:
// e.g. "POST /api/auth/login 200 45ms"
app.use(morgan('dev'));

// Parse incoming JSON request bodies (e.g., { "email": "...", "password": "..." }).
// The 10mb limit allows larger payloads for file uploads that include
// base64-encoded data.
app.use(express.json({ limit: '10mb' }));

// Parse URL-encoded form data (traditional HTML form submissions).
app.use(express.urlencoded({ extended: true }));

// --- RATE LIMITING (Brute-Force Protection) ---
// This is a critical security measure: it limits each IP address to a
// maximum of 20 requests per 15-minute window on the login and signup
// endpoints. If an attacker tries to guess a user's password by rapidly
// sending thousands of login attempts, they'll be blocked after 20 tries
// and must wait 15 minutes before trying again. This makes brute-force
// attacks impractically slow.
//
// Note: this works alongside the per-account lockout in loginAttempts.js.
// Rate limiting protects the ENDPOINT (by IP), while account lockout
// protects the ACCOUNT (by email). Together, they cover two different
// attack vectors.

// Basic brute-force protection on auth endpoints.
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,   // 15-minute sliding window
  max: 20,                      // max 20 requests per window per IP
  message: { error: 'Too many attempts, please try again later.' }
});
app.use('/api/auth/login', authLimiter);   // Apply to login endpoint
app.use('/api/auth/signup', authLimiter);  // Apply to signup endpoint

// ============================================================================
// API ROUTES
// ============================================================================
// Each app.use() call "mounts" a router at a specific URL path. When a
// request arrives at e.g. /api/files/upload, Express strips the "/api/files"
// prefix and passes "/upload" to the filesRoutes router, which has a handler
// for that path. This keeps the code organized — each route file handles
// one area of functionality.
// ============================================================================

// --- Routes ---
app.use('/api/auth', authRoutes);             // Authentication: signup, login, KBA, password reset
app.use('/api/files', filesRoutes);           // File operations: upload, send, download, versioning
app.use('/api/blockchain', blockchainRoutes); // Blockchain: view ledger, validate chain integrity
app.use('/api/groups', groupsRoutes);         // Groups: create, manage members, group file sharing
app.use('/api/admin', adminRoutes);           // Admin panel: user management, logs, alerts

// --- Static frontend ---
// Serve the HTML/CSS/JS files from the "public" folder. When someone visits
// http://localhost:3000/ in their browser, Express looks in /public for
// index.html, login.html, dashboard.html, etc., and serves them directly.
app.use(express.static(path.join(__dirname, 'public')));

// ============================================================================
// SOCKET.IO — Real-Time Communication
// ============================================================================
//
// HOW IT WORKS:
//   Normal HTTP is "request-response" — the browser asks, the server answers.
//   Socket.IO adds WebSockets on top, creating a persistent two-way channel.
//   This lets the server PUSH messages to connected browsers instantly,
//   without the browser having to keep asking "anything new?"
//
// ROOMS:
//   Socket.IO has a concept of "rooms" — named channels that sockets can
//   join. A message sent to a room reaches every socket in that room.
//
//   • Each user joins a room named after their email address. This is how
//     we send personal notifications (e.g., "you received a file from X").
//
//   • Admin users additionally join 'admin-room', where they receive:
//     - Live file traffic events (uploads, downloads, sends)
//     - Presence updates (who just came online/went offline)
//
// WHY THIS MATTERS FOR SECURITY:
//   Real-time notifications improve security awareness — admins can see
//   file transfers AS THEY HAPPEN, and users are immediately notified
//   when they receive files, rather than discovering them later.
// ============================================================================

// --- Socket.IO ---
// Every connection joins a room named after its email (for direct
// notifications). Admin accounts additionally join 'admin-room', which
// is where the live file-traffic feed and presence updates get
// broadcast - the admin dashboard listens there.
io.on('connection', (socket) => {

  // When a user logs in on the frontend, the browser sends a 'register'
  // event with their email. We join them to their personal room and
  // mark them as online in the presence tracker.
  socket.on('register', (email) => {
    socket.join(email);                 // Join the room named after their email
    presence.markOnline(socket.id, email); // Track that this socket = this user
    // Notify all admins that the online user list has changed
    io.to('admin-room').emit('presence-update', { online: presence.listOnline() });
  });

  // Admin users send 'register-admin' to join the admin broadcast room.
  // This is separate from their personal room — they get BOTH personal
  // notifications AND admin-level feeds.
  socket.on('register-admin', () => {
    socket.join('admin-room');
  });

  // When a browser tab is closed or loses connection, Socket.IO fires
  // 'disconnect'. We remove the user from the presence tracker and
  // notify admins so the "online users" panel updates in real time.
  socket.on('disconnect', () => {
    presence.markOffline(socket.id);
    io.to('admin-room').emit('presence-update', { online: presence.listOnline() });
  });
});

// Store the Socket.IO instance on the Express app so that route handlers
// can access it via req.app.get('io') to emit events (e.g., notifying a
// user that they received a file).
app.set('io', io);

// ============================================================================
// SERVER BOOT SEQUENCE
// ============================================================================
// The server doesn't start accepting requests until the database is ready.
// getDB() opens (or creates) the SQLite database and ensures all required
// tables exist. Only after that succeeds does server.listen() start
// accepting connections. If the database fails to initialize, the server
// exits immediately with an error — there's no point running without a DB.
// ============================================================================

// --- Boot ---
const PORT = process.env.PORT || 3000;

getDB()
  .then(() => {
    server.listen(PORT, () => {
      console.log(`Data Chain server running on http://localhost:${PORT}`);
    });
  })
  .catch((err) => {
    console.error('Failed to initialize database:', err);
    process.exit(1);   // Exit with error code 1 (non-zero = something went wrong)
  });
