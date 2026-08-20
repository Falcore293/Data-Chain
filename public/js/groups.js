// public/js/groups.js
// Handles the Groups panel: create a group, add members, list groups,
// and share files into a group (multi-recipient envelope encryption
// happens server-side in routes/groups.js).

let uploadTargetGroupId = null;

document.getElementById('createGroupBtn').addEventListener('click', async () => {
  const input = document.getElementById('newGroupName');
  const name = input.value.trim();
  const msgEl = document.getElementById('createGroupMsg');
  if (!name) return;

  try {
    const res = await fetch('/api/groups', {
      method: 'POST',
      headers: { ...authHeaders(), 'Content-Type': 'application/json' },
      body: JSON.stringify({ name })
    });
    const data = await res.json();

    if (!res.ok) {
      msgEl.className = 'msg error';
      msgEl.textContent = data.error || 'Could not create group';
    } else {
      msgEl.className = 'msg success';
      msgEl.textContent = `Group "${data.name}" created.`;
      input.value = '';
      loadGroups();
    }
  } catch (err) {
    msgEl.className = 'msg error';
    msgEl.textContent = 'Could not reach the server.';
  }
});

function groupCardHTML(g) {
  return `
    <div class="group-card" data-group-id="${g.id}">
      <div class="group-card-top">
        <div>
          <div class="group-name">${g.name}</div>
          <div class="group-meta">${g.memberCount} member${g.memberCount === 1 ? '' : 's'} · owner: ${g.ownerEmail}</div>
        </div>
        <button class="btn-small" onclick="openGroupUpload(${g.id}, '${g.name.replace(/'/g, "\\'")}')">Share a file</button>
      </div>
      <div class="group-members" id="members-${g.id}">Loading members...</div>
      ${g.isOwner ? `
        <div class="add-member-row">
          <input type="email" id="addMemberInput-${g.id}" placeholder="teammate@example.com">
          <button class="btn-small" onclick="addMember(${g.id})">Add member</button>
        </div>
        <div id="addMemberMsg-${g.id}" class="msg" style="margin-top:8px;"></div>
      ` : ''}
    </div>
  `;
}

async function loadGroupMembers(groupId) {
  try {
    const res = await fetch(`/api/groups/${groupId}/members`, { headers: authHeaders() });
    const data = await res.json();
    const el = document.getElementById(`members-${groupId}`);
    if (!el) return;
    el.innerHTML = data.members.map((m) => `<span class="member-chip">${m.memberEmail}</span>`).join('');
  } catch (err) {
    // silent - member list is secondary info
  }
}

async function loadGroups() {
  try {
    const res = await fetch('/api/groups', { headers: authHeaders() });
    const data = await res.json();
    const listEl = document.getElementById('groupList');

    if (!data.groups || data.groups.length === 0) {
      listEl.innerHTML = '<div class="empty-state">No groups yet. Create one above to start sharing a folder with your team.</div>';
      return;
    }

    listEl.innerHTML = data.groups.map(groupCardHTML).join('');
    data.groups.forEach((g) => loadGroupMembers(g.id));
  } catch (err) {
    document.getElementById('groupList').innerHTML = '<div class="empty-state">Could not load your groups.</div>';
  }
}

async function addMember(groupId) {
  const input = document.getElementById(`addMemberInput-${groupId}`);
  const msgEl = document.getElementById(`addMemberMsg-${groupId}`);
  const email = input.value.trim();
  if (!email) return;

  try {
    const res = await fetch(`/api/groups/${groupId}/members`, {
      method: 'POST',
      headers: { ...authHeaders(), 'Content-Type': 'application/json' },
      body: JSON.stringify({ email })
    });
    const data = await res.json();

    msgEl.className = res.ok ? 'msg success' : 'msg error';
    msgEl.textContent = data.message || data.error;

    if (res.ok) {
      input.value = '';
      loadGroupMembers(groupId);
      loadGroups(); // refresh member count
    }
  } catch (err) {
    msgEl.className = 'msg error';
    msgEl.textContent = 'Could not reach the server.';
  }
}

// ---------------------------------------------------------------------
// Share a file into a group
// ---------------------------------------------------------------------
function openGroupUpload(groupId, groupName) {
  uploadTargetGroupId = groupId;
  document.getElementById('groupUploadTitle').textContent = `Share File to ${groupName}`;
  document.getElementById('groupUploadForm').reset();
  document.getElementById('groupUploadMsg').className = 'msg';
  document.getElementById('groupUploadCustomHoursField').style.display = 'none';
  document.getElementById('groupUploadOverlay').style.display = 'flex';
}

document.getElementById('groupUploadCloseBtn').addEventListener('click', () => {
  document.getElementById('groupUploadOverlay').style.display = 'none';
  uploadTargetGroupId = null;
});

document.getElementById('groupUploadExpiry').addEventListener('change', (e) => {
  document.getElementById('groupUploadCustomHoursField').style.display = e.target.value === 'custom' ? 'block' : 'none';
});

document.getElementById('groupUploadForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  if (!uploadTargetGroupId) return;

  const fileInput = document.getElementById('groupUploadFile');
  const expiry = document.getElementById('groupUploadExpiry').value;
  const msgEl = document.getElementById('groupUploadMsg');
  const btn = document.getElementById('groupUploadBtn');

  if (!fileInput.files.length) return;

  btn.disabled = true;
  btn.textContent = 'Encrypting for all members...';

  const formData = new FormData();
  formData.append('file', fileInput.files[0]);
  formData.append('expiryType', expiry);
  if (expiry === 'custom') {
    formData.append('customHours', document.getElementById('groupUploadCustomHours').value);
  }

  try {
    const res = await fetch(`/api/groups/${uploadTargetGroupId}/upload`, {
      method: 'POST',
      headers: authHeaders(),
      body: formData
    });
    const data = await res.json();

    if (!res.ok) {
      msgEl.className = 'msg error';
      msgEl.textContent = data.error || 'Failed to share file';
    } else {
      msgEl.className = 'msg success';
      msgEl.textContent = `${data.message}. Block #${data.block.blockIndex} added to the ledger.`;
      loadMyFiles();
      setTimeout(() => {
        document.getElementById('groupUploadOverlay').style.display = 'none';
      }, 1200);
    }
  } catch (err) {
    msgEl.className = 'msg error';
    msgEl.textContent = 'Could not reach the server.';
  } finally {
    btn.disabled = false;
    btn.textContent = 'Encrypt & Share';
  }
});

// Load groups when the tab is opened.
document.querySelector('.nav-item[data-panel="groups"]').addEventListener('click', loadGroups);
