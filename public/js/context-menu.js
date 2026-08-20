// public/js/context-menu.js
// Right-click on a file card -> Add New Version / View Versions.
// Relies on authHeaders(), loadMyFiles(), formatBytes(), downloadFile()
// from files.js, which loads before this script.

const contextMenu = document.getElementById('contextMenu');
const modalOverlay = document.getElementById('modalOverlay');
const modalTitle = document.getElementById('modalTitle');
const modalBody = document.getElementById('modalBody');

let activeFileId = null;
let activeCanManage = false;

// --- Context menu open/close ---
// Delegated to the whole document (not just #fileList) so this also
// works on the Shared Files list, which renders into a separate container.
document.addEventListener('contextmenu', (e) => {
  const card = e.target.closest('.file-card');
  if (!card) return;
  e.preventDefault();

  activeFileId = card.dataset.id;
  activeCanManage = card.dataset.canManage === 'true';

  // Only the owner can add a new version - grey it out otherwise,
  // but everyone with access can still view history.
  const addVersionItem = document.getElementById('ctxAddVersion');
  const deleteItem = document.getElementById('ctxDelete');
  if (activeCanManage) {
    addVersionItem.classList.remove('disabled');
    deleteItem.classList.remove('disabled');
    deleteItem.style.display = 'block';
  } else {
    addVersionItem.classList.add('disabled');
    deleteItem.classList.add('disabled');
    deleteItem.style.display = 'none';
  }

  contextMenu.style.display = 'block';
  contextMenu.style.left = `${e.pageX}px`;
  contextMenu.style.top = `${e.pageY}px`;
});

document.addEventListener('click', (e) => {
  if (!contextMenu.contains(e.target)) {
    contextMenu.style.display = 'none';
  }
});

// --- Modal open/close ---
function openModal(title, bodyHTML) {
  modalTitle.textContent = title;
  modalBody.innerHTML = bodyHTML;
  modalOverlay.style.display = 'flex';
}

function closeModal() {
  modalOverlay.style.display = 'none';
  modalBody.innerHTML = '';
}

document.getElementById('modalCloseBtn').addEventListener('click', closeModal);
modalOverlay.addEventListener('click', (e) => {
  if (e.target === modalOverlay) closeModal();
});

// ---------------------------------------------------------------------
// Add New Version
// ---------------------------------------------------------------------
document.getElementById('ctxAddVersion').addEventListener('click', () => {
  contextMenu.style.display = 'none';
  if (!activeCanManage) return; // disabled item, ignore clicks

  openModal('Add New Version', `
    <p class="modal-sub">Uploading a new version does not touch or invalidate old versions — every version keeps its own hash and stays downloadable.</p>
    <div id="versionUploadMsg" class="msg"></div>
    <div class="field">
      <label for="versionUploadFile">New file content</label>
      <input type="file" id="versionUploadFile">
    </div>
    <button class="btn-primary" id="versionUploadBtn">Encrypt & Add Version</button>
  `);

  document.getElementById('versionUploadBtn').addEventListener('click', async () => {
    const input = document.getElementById('versionUploadFile');
    const msgEl = document.getElementById('versionUploadMsg');
    const btn = document.getElementById('versionUploadBtn');

    if (!input.files.length) return;

    btn.disabled = true;
    btn.textContent = 'Encrypting...';

    const formData = new FormData();
    formData.append('file', input.files[0]);

    try {
      const res = await fetch(`/api/files/${activeFileId}/version`, {
        method: 'POST',
        headers: authHeaders(),
        body: formData
      });
      const data = await res.json();

      if (!res.ok) {
        msgEl.className = 'msg error';
        msgEl.textContent = data.error || 'Could not add version';
      } else {
        msgEl.className = 'msg success';
        msgEl.textContent = `Version ${data.versionNumber} added. Block #${data.block.blockIndex} logged on the chain.`;
        loadMyFiles();
        setTimeout(closeModal, 1400);
      }
    } catch (err) {
      msgEl.className = 'msg error';
      msgEl.textContent = 'Could not reach the server.';
    } finally {
      btn.disabled = false;
      btn.textContent = 'Encrypt & Add Version';
    }
  });
});

// ---------------------------------------------------------------------
// View Versions
// ---------------------------------------------------------------------
document.getElementById('ctxViewVersions').addEventListener('click', async () => {
  contextMenu.style.display = 'none';
  openModal('Version History', '<div class="empty-state">Loading...</div>');

  try {
    const res = await fetch(`/api/files/${activeFileId}/versions`, { headers: authHeaders() });
    const data = await res.json();

    if (!res.ok) {
      modalBody.innerHTML = `<div class="msg error" style="display:block;">${data.error || 'Could not load versions'}</div>`;
      return;
    }

    modalBody.innerHTML = data.versions.map((v) => `
      <div class="version-row">
        <div>
          <span class="v-num">v${v.versionNumber}</span>
          <div class="v-meta">
            ${new Date(v.createdAt).toLocaleString()} · by ${v.uploadedBy}<br>
            Hash: ${v.fileHash.slice(0, 20)}... · ${formatBytes(v.fileSize)}
          </div>
        </div>
        <button class="btn-small" onclick="downloadFile(${activeFileId}, ${v.versionNumber})">Download</button>
      </div>
    `).join('') || '<div class="empty-state">No versions found.</div>';
  } catch (err) {
    modalBody.innerHTML = '<div class="msg error" style="display:block;">Could not reach the server.</div>';
  }
});

// ---------------------------------------------------------------------
// Set Access — same options as Upload/Send: none, 1h, 1d, 3d, custom
// ---------------------------------------------------------------------
document.getElementById('ctxSetAccess').addEventListener('click', () => {
  contextMenu.style.display = 'none';
  if (!activeCanManage) return;

  openModal('Set Access', `
    <p class="modal-sub">Controls how long this file stays downloadable. Applies immediately.</p>
    <div id="accessMsg" class="msg"></div>
    <div class="field">
      <label for="accessExpiry">Access duration</label>
      <select id="accessExpiry">
        <option value="none">Unlimited</option>
        <option value="1h">1 hour</option>
        <option value="1d">1 day</option>
        <option value="3d">3 days</option>
        <option value="custom">Custom</option>
      </select>
    </div>
    <div class="field" id="accessCustomHoursField" style="display:none;">
      <label for="accessCustomHours">Custom duration (hours)</label>
      <input type="number" id="accessCustomHours" min="1" placeholder="e.g. 6">
    </div>
    <button class="btn-primary" id="saveAccessBtn">Save Access Setting</button>
  `);

  document.getElementById('accessExpiry').addEventListener('change', (e) => {
    document.getElementById('accessCustomHoursField').style.display = e.target.value === 'custom' ? 'block' : 'none';
  });

  document.getElementById('saveAccessBtn').addEventListener('click', async () => {
    const expiryType = document.getElementById('accessExpiry').value;
    const customHours = document.getElementById('accessCustomHours').value;
    const msgEl = document.getElementById('accessMsg');
    const btn = document.getElementById('saveAccessBtn');

    btn.disabled = true;
    btn.textContent = 'Saving...';

    try {
      const res = await fetch(`/api/files/${activeFileId}/access`, {
        method: 'PATCH',
        headers: { ...authHeaders(), 'Content-Type': 'application/json' },
        body: JSON.stringify({ expiryType, customHours })
      });
      const data = await res.json();

      if (!res.ok) {
        msgEl.className = 'msg error';
        msgEl.textContent = data.error || 'Could not update access setting';
      } else {
        msgEl.className = 'msg success';
        msgEl.textContent = `Updated. Block #${data.block.blockIndex} logged on the chain.`;
        loadMyFiles();
        setTimeout(closeModal, 1200);
      }
    } catch (err) {
      msgEl.className = 'msg error';
      msgEl.textContent = 'Could not reach the server.';
    } finally {
      btn.disabled = false;
      btn.textContent = 'Save Access Setting';
    }
  });
});

// ---------------------------------------------------------------------
// Delete File (via context menu)
// ---------------------------------------------------------------------
document.getElementById('ctxDelete').addEventListener('click', () => {
  contextMenu.style.display = 'none';
  if (!activeCanManage) return;

  // Find the file card to get the file name
  const card = document.querySelector(`.file-card[data-id="${activeFileId}"]`);
  const fileName = card ? card.querySelector('.file-name').textContent.trim() : 'this file';

  openModal('Delete File', `
    <p class="modal-sub" style="color: var(--error);">
      ⚠️ This action is permanent and cannot be undone. All versions and encrypted data will be removed from the server.
    </p>
    <div id="deleteMsg" class="msg"></div>
    <div style="background: rgba(248,113,113,0.08); border: 1px solid rgba(248,113,113,0.2); border-radius: 10px; padding: 14px; margin-bottom: 18px;">
      <div style="font-size: 0.85rem; color: var(--text-dim);">File to delete:</div>
      <div style="font-weight: 600; margin-top: 4px;">${fileName}</div>
    </div>
    <button class="btn-primary" id="confirmDeleteBtn" style="background: linear-gradient(135deg, #dc2626, #b91c1c);">Permanently Delete</button>
  `);

  document.getElementById('confirmDeleteBtn').addEventListener('click', async () => {
    const msgEl = document.getElementById('deleteMsg');
    const btn = document.getElementById('confirmDeleteBtn');

    btn.disabled = true;
    btn.textContent = 'Deleting...';

    try {
      const res = await fetch(`/api/files/${activeFileId}`, {
        method: 'DELETE',
        headers: authHeaders()
      });
      const data = await res.json();

      if (!res.ok) {
        msgEl.className = 'msg error';
        msgEl.textContent = data.error || 'Could not delete file';
      } else {
        msgEl.className = 'msg success';
        msgEl.textContent = `Deleted. Block #${data.block.blockIndex} logged on the chain.`;
        loadMyFiles();
        setTimeout(closeModal, 1200);
      }
    } catch (err) {
      msgEl.className = 'msg error';
      msgEl.textContent = 'Could not reach the server.';
    } finally {
      btn.disabled = false;
      btn.textContent = 'Permanently Delete';
    }
  });
});

