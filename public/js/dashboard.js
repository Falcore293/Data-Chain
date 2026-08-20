// public/js/dashboard.js

const token = localStorage.getItem('dc_token');
const email = localStorage.getItem('dc_email');

// Auth guard - bounce back to login if there's no session.
if (!token) {
  window.location.href = 'login.html';
}

document.getElementById('userEmail').textContent = email || '';

// Single shared Socket.IO connection for the whole dashboard - created
// here (first script to load) so every other script (files.js,
// admin.js) can reuse window.dcSocket instead of opening their own
// separate connections.
if (window.io) {
  window.dcSocket = io();
  window.dcSocket.emit('register', email);
}

document.getElementById('logoutBtn').addEventListener('click', () => {
  localStorage.removeItem('dc_token');
  localStorage.removeItem('dc_email');
  window.location.href = 'login.html';
});

// Sidebar navigation - swap active panel.
document.querySelectorAll('.nav-item').forEach((item) => {
  item.addEventListener('click', () => {
    document.querySelectorAll('.nav-item').forEach((i) => i.classList.remove('active'));
    document.querySelectorAll('.panel').forEach((p) => p.classList.remove('active'));

    item.classList.add('active');
    document.getElementById(`panel-${item.dataset.panel}`).classList.add('active');
  });
});

// Account info: whether to show the Admin nav item, and current 2FA
// state for the Settings panel. Fetched once on load.
let currentUser = { role: 'user', twoFactorEnabled: false };

async function loadCurrentUser() {
  try {
    const res = await fetch('/api/auth/me', { headers: { Authorization: `Bearer ${token}` } });
    if (!res.ok) return;
    currentUser = await res.json();

    if (currentUser.role === 'admin') {
      document.getElementById('adminNavItem').style.display = 'flex';
      const scopeAllBtn = document.getElementById('scopeAllBtn');
      if (scopeAllBtn) scopeAllBtn.style.display = 'inline-block';
      // Join the admin broadcast room now that we know for sure this
      // account is an admin - separate from the plain 'register' event
      // so there's no race between role loading and socket connection.
      if (window.dcSocket) window.dcSocket.emit('register-admin');
    }
    updateTwoFaUI();
  } catch (err) {
    // non-fatal - dashboard still works without this
  }
}

function updateTwoFaUI() {
  const statusEl = document.getElementById('twoFaStatus');
  if (!statusEl) return;

  if (currentUser.twoFactorEnabled) {
    statusEl.textContent = '2-step verification is ON — security questions are required at login.';
    statusEl.className = 'msg success';
  } else {
    statusEl.textContent = '2-step verification is OFF — login only needs your password. Your security questions still work for "Forgot password".';
    statusEl.className = 'msg';
  }
  statusEl.style.display = 'block';
}

// If an admin suspends this account mid-session, react immediately
// instead of waiting for the JWT to expire or the next page load.
if (window.dcSocket) {
  window.dcSocket.on('account-status', (data) => {
    if (data.suspended) {
      alert('Your account has been suspended by an administrator. You will be logged out.');
      localStorage.removeItem('dc_token');
      localStorage.removeItem('dc_email');
      window.location.href = 'login.html';
    }
  });
}

loadCurrentUser();
