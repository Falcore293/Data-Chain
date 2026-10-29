// public/js/admin.js
// Only ever visible/callable if the account's role is 'admin' - the
// nav item is hidden client-side AND every /api/admin/* route double
// checks the role server-side, so this is convenience, not the actual
// security boundary.

const ADMIN_TABS = ['Users', 'Logs', 'Alerts', 'Requests', 'Online', 'Traffic'];

function adminTabSwitch(active) {
  ADMIN_TABS.forEach((name) => {
    document.getElementById(`admin${name}Section`).style.display = name === active ? 'block' : 'none';
    document.getElementById(`adminTab${name}`).style.borderColor = name === active ? 'var(--accent)' : '';
    document.getElementById(`adminTab${name}`).style.color = name === active ? 'var(--accent-bright)' : '';
  });
}

document.getElementById('adminTabUsers').addEventListener('click', () => { adminTabSwitch('Users'); loadAdminUsers(); });
document.getElementById('adminTabLogs').addEventListener('click', () => { adminTabSwitch('Logs'); loadAdminLogs(); });
document.getElementById('adminTabAlerts').addEventListener('click', () => { adminTabSwitch('Alerts'); loadAdminAlerts(); });
document.getElementById('adminTabRequests').addEventListener('click', () => { adminTabSwitch('Requests'); loadAdminRequests(); });
document.getElementById('adminTabOnline').addEventListener('click', () => { adminTabSwitch('Online'); loadOnlineUsers(); });
document.getElementById('adminTabTraffic').addEventListener('click', () => { adminTabSwitch('Traffic'); loadFileTraffic(); });

// ---------------------------------------------------------------------
// Users (+ Suspend / Unsuspend)
// ---------------------------------------------------------------------
let onlineEmails = [];

async function loadAdminUsers() {
  const el = document.getElementById('adminUserList');
  el.innerHTML = 'Loading...';
  try {
    const res = await fetch('/api/admin/users', { headers: authHeaders() });
    const data = await res.json();
    if (!res.ok) { el.innerHTML = `<div class="empty-state">${data.error}</div>`; return; }

    onlineEmails = data.users.filter((u) => u.online).map((u) => u.email);

    el.innerHTML = data.users.map((u) => `
      <div class="file-card">
        <div class="file-card-top">
          <div>
            <div class="file-name">
              ${u.online ? '<span style="color:var(--success);">●</span> ' : '<span style="color:var(--text-dim);">●</span> '}
              ${u.email} ${u.suspended ? '<span class="badge expired" style="margin-left:6px;">suspended</span>' : ''}
            </div>
            <div class="file-meta">
              Role: ${u.role} · KBA: ${(u.kbaEnabled ?? u.twoFactorEnabled) ? 'on' : 'off'} · ${u.filesOwned} file(s) owned<br>
              Joined ${new Date(u.createdAt).toLocaleString()}
            </div>
          </div>
          <div class="file-actions" style="margin-top:0;">
            ${u.role === 'admin' ? '' : `<button class="btn-small" onclick="toggleSuspend('${u.email}', ${!u.suspended})">${u.suspended ? 'Unsuspend' : 'Suspend'}</button>`}
          </div>
        </div>
      </div>
    `).join('') || '<div class="empty-state">No users.</div>';
  } catch (err) {
    el.innerHTML = '<div class="empty-state">Could not load users.</div>';
  }
}

async function toggleSuspend(targetEmail, suspend) {
  if (suspend && !confirm(`Suspend ${targetEmail}? This immediately blocks their uploads, sends, and downloads.`)) return;

  try {
    const res = await fetch('/api/admin/suspend-user', {
      method: 'POST',
      headers: { ...authHeaders(), 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: targetEmail, suspend })
    });
    const data = await res.json();
    if (!res.ok) { alert(data.error); return; }
    loadAdminUsers();
  } catch (err) {
    alert('Could not reach the server.');
  }
}

// ---------------------------------------------------------------------
// Logs
// ---------------------------------------------------------------------
async function loadAdminLogs() {
  const el = document.getElementById('adminLogList');
  el.innerHTML = 'Loading...';
  try {
    const res = await fetch('/api/admin/logs', { headers: authHeaders() });
    const data = await res.json();
    if (!res.ok) { el.innerHTML = `<div class="empty-state">${data.error}</div>`; return; }

    el.innerHTML = data.logs.map((l) => {
      const isBad = l.action === 'denied' || l.action === 'failed';
      return `
      <div class="block-card">
        <div class="block-index" style="color:${isBad ? 'var(--error)' : 'var(--accent-bright)'};">${l.type}</div>
        <div>
          <span class="block-action" style="border-color:${isBad ? 'rgba(248,113,113,0.35)' : 'rgba(74,222,128,0.35)'}; color:${isBad ? 'var(--error)' : 'var(--success)'};">${l.action}</span>
          <span class="file-name" style="font-size:0.85rem;">${l.email}</span>
          <div class="block-meta">
            ${new Date(l.timestamp).toLocaleString()}${l.detail ? ' · ' + l.detail : ''}
          </div>
        </div>
      </div>
    `;
    }).join('') || '<div class="empty-state">No logs yet.</div>';
  } catch (err) {
    el.innerHTML = '<div class="empty-state">Could not load logs.</div>';
  }
}

document.getElementById('exportLogsBtn').addEventListener('click', async () => {
  const btn = document.getElementById('exportLogsBtn');
  btn.disabled = true;
  btn.textContent = 'Exporting...';

  try {
    const res = await fetch('/api/admin/logs/export', { headers: authHeaders() });
    if (!res.ok) { alert('Export failed'); return; }
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `datachain-logs-${Date.now()}.csv`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  } catch (err) {
    alert('Could not reach the server.');
  } finally {
    btn.disabled = false;
    btn.textContent = '⬇ Export CSV';
  }
});

// ---------------------------------------------------------------------
// Security Alerts
// ---------------------------------------------------------------------
async function loadAdminAlerts() {
  const el = document.getElementById('adminAlertList');
  el.innerHTML = 'Loading...';
  try {
    const res = await fetch('/api/admin/security-alerts', { headers: authHeaders() });
    const data = await res.json();
    if (!res.ok) { el.innerHTML = `<div class="empty-state">${data.error}</div>`; return; }

    el.innerHTML = data.alerts.map((a) => `
      <div class="file-card">
        <div class="file-card-top">
          <div>
            <div class="file-name" style="color:var(--error);">⚠ ${a.eventType} — ${a.email}</div>
            <div class="file-meta">${a.detail || ''} · ${new Date(a.timestamp).toLocaleString()}</div>
          </div>
        </div>
      </div>
    `).join('') || '<div class="empty-state">No security alerts. Good sign.</div>';
  } catch (err) {
    el.innerHTML = '<div class="empty-state">Could not load alerts.</div>';
  }
}

// ---------------------------------------------------------------------
// Account Termination Requests
// ---------------------------------------------------------------------
async function loadAdminRequests() {
  const el = document.getElementById('adminRequestsList');
  el.innerHTML = 'Loading...';
  try {
    const res = await fetch('/api/admin/deletion-requests?status=pending', { headers: authHeaders() });
    const data = await res.json();
    if (!res.ok) { el.innerHTML = `<div class="empty-state">${data.error}</div>`; return; }

    el.innerHTML = data.requests.map((r) => `
      <div class="file-card">
        <div class="file-card-top">
          <div>
            <div class="file-name">${r.email}</div>
            <div class="file-meta">"${r.reason}"<br>Requested ${new Date(r.requestedAt).toLocaleString()}</div>
          </div>
        </div>
        <div class="file-actions">
          <button class="btn-small" style="border-color:var(--error); color:var(--error);" onclick="resolveRequest(${r.id}, 'approve', '${r.email}')">Approve (Delete Account)</button>
          <button class="btn-small" onclick="resolveRequest(${r.id}, 'reject', '${r.email}')">Reject</button>
        </div>
      </div>
    `).join('') || '<div class="empty-state">No pending requests.</div>';
  } catch (err) {
    el.innerHTML = '<div class="empty-state">Could not load requests.</div>';
  }
}

async function resolveRequest(id, action, targetEmail) {
  if (action === 'approve' && !confirm(`Permanently delete ${targetEmail}'s account? This cannot be undone.`)) return;

  try {
    const res = await fetch(`/api/admin/deletion-requests/${id}/${action}`, {
      method: 'POST',
      headers: authHeaders()
    });
    const data = await res.json();
    if (!res.ok) { alert(data.error); return; }
    loadAdminRequests();
  } catch (err) {
    alert('Could not reach the server.');
  }
}

// ---------------------------------------------------------------------
// Online Now
// ---------------------------------------------------------------------
async function loadOnlineUsers() {
  const el = document.getElementById('adminOnlineList');
  el.innerHTML = 'Loading...';
  try {
    const res = await fetch('/api/admin/online-users', { headers: authHeaders() });
    const data = await res.json();
    renderOnlineUsers(data.online);
  } catch (err) {
    el.innerHTML = '<div class="empty-state">Could not load online users.</div>';
  }
}

function renderOnlineUsers(online) {
  const el = document.getElementById('adminOnlineList');
  if (!el) return;
  el.innerHTML = online.length
    ? online.map((e) => `<span class="member-chip" style="border-color:rgba(74,222,128,0.35); color:var(--success);">● ${e}</span>`).join('')
    : '<div class="empty-state">Nobody online right now.</div>';
}

// Live updates - server pushes this whenever someone connects/disconnects.
if (window.dcSocket) {
  window.dcSocket.on('presence-update', (data) => {
    renderOnlineUsers(data.online);
  });
}

// ---------------------------------------------------------------------
// File Traffic
// ---------------------------------------------------------------------
function trafficRowHTML(e) {
  const label = { upload: 'Upload', send: 'Send', download: 'Download', version: 'New version', 'group-upload': 'Group share' }[e.action] || e.action;
  const detail = e.to ? `to ${e.to}` : (e.groupName ? `in ${e.groupName}` : '');
  return `
    <div class="block-card">
      <div class="block-index" style="color:var(--accent-bright);">${label}</div>
      <div>
        <span class="file-name" style="font-size:0.85rem;">${e.email} ${detail}</span>
        <div class="block-meta">${e.fileName || ''} ${e.size ? '· ' + formatBytes(e.size) : ''} · ${new Date(e.timestamp).toLocaleString()}</div>
      </div>
    </div>
  `;
}

async function loadFileTraffic() {
  const el = document.getElementById('adminTrafficList');
  el.innerHTML = 'Loading...';
  try {
    const res = await fetch('/api/admin/file-traffic', { headers: authHeaders() });
    const data = await res.json();
    if (!res.ok) { el.innerHTML = `<div class="empty-state">${data.error}</div>`; return; }

    el.innerHTML = data.events.map((e) => trafficRowHTML({ ...e, timestamp: e.timestamp })).join('')
      || '<div class="empty-state">No file activity yet.</div>';
  } catch (err) {
    el.innerHTML = '<div class="empty-state">Could not load traffic.</div>';
  }
}

// Live feed - prepend new events as they happen while this tab is open.
if (window.dcSocket) {
  window.dcSocket.on('file-traffic', (event) => {
    const el = document.getElementById('adminTrafficList');
    if (!el || document.getElementById('adminTrafficSection').style.display === 'none') return;
    const emptyState = el.querySelector('.empty-state');
    if (emptyState) emptyState.remove();
    el.insertAdjacentHTML('afterbegin', trafficRowHTML(event));
  });
}

// Load Users the first time the Admin tab is opened.
document.getElementById('adminNavItem').addEventListener('click', () => {
  adminTabSwitch('Users');
  loadAdminUsers();
});
