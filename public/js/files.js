// public/js/files.js
// Handles Upload, Send, My Files, and download-with-client-side-decryption.
// Right-click actions (add version / view versions) live in context-menu.js,
// which relies on authHeaders(), loadMyFiles(), formatBytes(), and
// downloadFile() defined here.

const dcToken = localStorage.getItem('dc_token');
const dcEmail = localStorage.getItem('dc_email');

// The decrypted private key lives ONLY in this variable, for this tab,
// for this page load. It is never written to localStorage or sent
// anywhere — that would defeat the entire point of keeping it local.
let unlockedPrivateKeyPem = null;

function authHeaders() {
  return { Authorization: `Bearer ${dcToken}` };
}

function setKeyUnlocked(state) {
  const dot = document.getElementById('keyDot');
  const text = document.getElementById('keyStatusText');
  if (state) {
    dot.classList.add('unlocked');
    text.textContent = `Private key unlocked for ${dcEmail}`;
  } else {
    dot.classList.remove('unlocked');
    text.textContent = 'Private key locked — needed to download files';
  }
}

document.getElementById('unlockKeyBtn').addEventListener('click', async () => {
  const fileInput = document.getElementById('keyFileInput');
  const password = document.getElementById('keyPassword').value;
  const btn = document.getElementById('unlockKeyBtn');

  if (!fileInput.files.length) return alert('Select your .datachain-key.json file first.');
  if (!password) return alert('Enter your account password.');

  btn.disabled = true;
  btn.textContent = 'Unlocking...';

  try {
    const text = await fileInput.files[0].text();
    const bundle = JSON.parse(text);

    if (bundle.email !== dcEmail) {
      throw new Error(`This key file belongs to ${bundle.email}, not ${dcEmail}.`);
    }

    unlockedPrivateKeyPem = decryptPrivateKeyBundle(bundle, password);
    setKeyUnlocked(true);
    document.getElementById('keyPassword').value = '';
  } catch (err) {
    unlockedPrivateKeyPem = null;
    setKeyUnlocked(false);
    alert(err.message || 'Could not unlock private key. Check your file and password.');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Unlock';
  }
});

function showPanelMsg(id, text, type) {
  const el = document.getElementById(id);
  el.textContent = text;
  el.className = `msg ${type}`;
}

function toggleCustomHours(selectId, fieldId) {
  const select = document.getElementById(selectId);
  const field = document.getElementById(fieldId);
  select.addEventListener('change', () => {
    field.style.display = select.value === 'custom' ? 'block' : 'none';
  });
}
toggleCustomHours('uploadExpiry', 'uploadCustomHoursField');
toggleCustomHours('sendExpiry', 'sendCustomHoursField');

// ---------------------------------------------------------------------
// Upload
// ---------------------------------------------------------------------
document.getElementById('uploadForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const btn = document.getElementById('uploadBtn');
  const fileInput = document.getElementById('uploadFile');
  const expiry = document.getElementById('uploadExpiry').value;

  if (!fileInput.files.length) return;

  btn.disabled = true;
  btn.textContent = 'Encrypting...';

  const formData = new FormData();
  formData.append('file', fileInput.files[0]);
  formData.append('expiryType', expiry);
  if (expiry === 'custom') {
    formData.append('customHours', document.getElementById('uploadCustomHours').value);
  }

  try {
    const res = await fetch('/api/files/upload', {
      method: 'POST',
      headers: authHeaders(),
      body: formData
    });
    const data = await res.json();

    if (!res.ok) {
      showPanelMsg('uploadMsg', data.error || 'Upload failed', 'error');
    } else {
      showPanelMsg('uploadMsg', `Encrypted and stored. Block #${data.block.blockIndex} added to the ledger. Hash: ${data.fileHash.slice(0, 16)}...`, 'success');
      e.target.reset();
      loadMyFiles();
    }
  } catch (err) {
    showPanelMsg('uploadMsg', 'Could not reach the server.', 'error');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Encrypt & Upload';
  }
});

// ---------------------------------------------------------------------
// Send
// ---------------------------------------------------------------------
document.getElementById('sendForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const btn = document.getElementById('sendBtn');
  const fileInput = document.getElementById('sendFile');

  if (!fileInput.files.length) return;

  btn.disabled = true;
  btn.textContent = 'Encrypting for recipient...';

  const formData = new FormData();
  formData.append('file', fileInput.files[0]);
  formData.append('recipientEmail', document.getElementById('recipientEmail').value.trim());
  formData.append('expiryType', document.getElementById('sendExpiry').value);
  if (document.getElementById('sendExpiry').value === 'custom') {
    formData.append('customHours', document.getElementById('sendCustomHours').value);
  }

  try {
    const res = await fetch('/api/files/send', {
      method: 'POST',
      headers: authHeaders(),
      body: formData
    });
    const data = await res.json();

    if (!res.ok) {
      showPanelMsg('sendMsg', data.error || 'Send failed', 'error');
    } else {
      showPanelMsg('sendMsg', `${data.message}. Block #${data.block.blockIndex} added to the ledger.`, 'success');
      e.target.reset();
      loadMyFiles();
    }
  } catch (err) {
    showPanelMsg('sendMsg', 'Could not reach the server.', 'error');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Encrypt & Send';
  }
});

// ---------------------------------------------------------------------
// My Files / Shared Files
// ---------------------------------------------------------------------
function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function fileExtension(name) {
  const parts = name.split('.');
  return parts.length > 1 ? parts.pop().toUpperCase() : '—';
}

function fileCardHTML(f) {
  const directionBadge = { personal: 'personal', sent: 'sent', received: 'received', group: 'group' }[f.direction];
  const directionLabel = {
    personal: 'Personal',
    sent: `Sent to ${f.receiverEmail}`,
    received: `From ${f.ownerEmail}`,
    group: `Group: ${f.groupName}`
  }[f.direction];

  const accessLabel = f.expiryType === 'none'
    ? 'Unlimited access'
    : `Access until ${new Date(f.expiresAt).toLocaleString()}`;

  return `
    <div class="file-card" data-id="${f.id}" data-can-manage="${f.canManage}">
      <div class="file-card-top">
        <div>
          <div class="file-name">${f.originalName} ${f.latestVersion > 1 ? `<span class="badge" style="margin-left:6px;">v${f.latestVersion}</span>` : ''}</div>
          <div class="file-meta">
            ${directionLabel} · ${fileExtension(f.originalName)} · ${formatBytes(f.fileSize)}<br>
            SHA-256: ${f.fileHash.slice(0, 24)}...<br>
            ${accessLabel} · ${f.downloadCount} download(s) so far
          </div>
        </div>
        <div style="display:flex; flex-direction:column; align-items:flex-end; gap:6px;">
          <span class="badge ${directionBadge}">${directionBadge}</span>
          ${f.expired ? '<span class="badge expired">expired</span>' : ''}
        </div>
      </div>
      <div class="file-actions">
        <button class="btn-small" ${f.expired ? 'disabled' : ''} onclick="downloadFile(${f.id})">Download</button>
        ${f.canManage && f.direction === 'personal' ? `<button class="btn-small btn-danger" onclick="deleteFile(${f.id}, '${f.originalName.replace(/'/g, "\\'")}')">Delete</button>` : ''}
      </div>
    </div>
  `;
}

function sortFiles(files, sortBy) {
  const copy = [...files];
  if (sortBy === 'name') {
    copy.sort((a, b) => a.originalName.localeCompare(b.originalName));
  } else if (sortBy === 'type') {
    copy.sort((a, b) => fileExtension(a.originalName).localeCompare(fileExtension(b.originalName)) || a.originalName.localeCompare(b.originalName));
  } else {
    copy.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)); // date, newest first
  }
  return copy;
}

let allFilesCache = [];

function renderFileLists() {
  const personal = allFilesCache.filter((f) => f.direction === 'personal');
  const shared = allFilesCache.filter((f) => f.direction !== 'personal');

  const myFilesSort = document.getElementById('myFilesSort').value;
  const sharedFilesSort = document.getElementById('sharedFilesSort').value;

  const myListEl = document.getElementById('fileList');
  myListEl.innerHTML = personal.length
    ? sortFiles(personal, myFilesSort).map(fileCardHTML).join('')
    : '<div class="empty-state">No personal files yet. Use Upload File to store one just for yourself.</div>';

  const sharedListEl = document.getElementById('sharedFileList');
  sharedListEl.innerHTML = shared.length
    ? sortFiles(shared, sharedFilesSort).map(fileCardHTML).join('')
    : '<div class="empty-state">Nothing shared yet — send a file, join a group, or wait for someone to share with you.</div>';
}

document.getElementById('myFilesSort').addEventListener('change', renderFileLists);
document.getElementById('sharedFilesSort').addEventListener('change', renderFileLists);

async function loadMyFiles() {
  try {
    const res = await fetch('/api/files/my-files', { headers: authHeaders() });
    const data = await res.json();
    allFilesCache = data.files || [];
    renderFileLists();
  } catch (err) {
    showPanelMsg('fileListMsg', 'Could not load your files.', 'error');
  }
}

// Fetches the encrypted envelope, decrypts it entirely in the browser
// using the unlocked private key, verifies the SHA-256 hash matches what
// was recorded for that version, then triggers a real file download.
// Pass a versionNumber to download an older version instead of the latest.
async function downloadFile(id, versionNumber) {
  if (!unlockedPrivateKeyPem) {
    alert('Unlock your private key first using the bar at the top of the page.');
    return;
  }

  try {
    const endpoint = versionNumber
      ? `/api/files/${id}/download?version=${versionNumber}`
      : `/api/files/${id}/download`;
    const res = await fetch(endpoint, { headers: authHeaders() });
    const data = await res.json();

    if (!res.ok) {
      alert(data.error || 'Download failed');
      return;
    }

    const aesKeyBytes = unwrapAESKey(unlockedPrivateKeyPem, data.encryptedKey);
    const fileBytes = decryptFile(data.encryptedFile, data.iv, data.authTag, aesKeyBytes);

    const actualHash = sha256Hex(fileBytes);
    if (actualHash !== data.fileHash) {
      alert('Integrity check failed — decrypted file hash does not match the recorded hash. The file may be corrupted.');
      return;
    }

    const blob = new Blob([fileBytes]);
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = data.originalName;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);

    showPanelMsg('fileListMsg', `"${data.originalName}" (v${data.versionNumber}) decrypted and downloaded — integrity verified.`, 'success');
    loadMyFiles();
  } catch (err) {
    alert(`Decryption failed: ${err.message}\n\nIf you just unlocked your key, make sure it's the key for this account and the password was correct.`);
  }
}

// ---------------------------------------------------------------------
// Delete File
// ---------------------------------------------------------------------
async function deleteFile(id, fileName) {
  const confirmed = confirm(`Are you sure you want to permanently delete "${fileName}"?\n\nThis action cannot be undone. All versions of this file will be removed.`);
  if (!confirmed) return;

  try {
    const res = await fetch(`/api/files/${id}`, {
      method: 'DELETE',
      headers: authHeaders()
    });
    const data = await res.json();

    if (!res.ok) {
      showPanelMsg('fileListMsg', data.error || 'Delete failed', 'error');
    } else {
      showPanelMsg('fileListMsg', `"${fileName}" permanently deleted. Block #${data.block.blockIndex} logged on the chain.`, 'success');
      loadMyFiles();
    }
  } catch (err) {
    showPanelMsg('fileListMsg', 'Could not reach the server.', 'error');
  }
}

// ---------------------------------------------------------------------
// Real-time: notify when someone sends you a file
// ---------------------------------------------------------------------
if (window.dcSocket) {
  window.dcSocket.on('file-received', (payload) => {
    showPanelMsg('fileListMsg', `New file "${payload.originalName}" received from ${payload.from}`, 'success');
    loadMyFiles();
  });
}

loadMyFiles();
