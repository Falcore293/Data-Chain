// public/js/blockchain.js
// Renders the transaction ledger and runs the chain-validation check.

let chainScope = 'mine';

function blockCardHTML(b) {
  const time = new Date(b.timestamp).toLocaleString();
  return `
    <div class="block-card">
      <div class="block-index">#${b.blockIndex}</div>
      <div>
        <span class="block-action ${b.action}">${b.action}</span>
        <span class="file-name" style="font-size:0.85rem;">${b.sender}${b.receiver ? ` → ${b.receiver}` : ''}</span>
        <div class="block-meta">
          ${time}<br>
          File hash: ${b.fileHash}<br>
          Prev hash: ${b.previousHash.slice(0, 24)}...<br>
          Block hash: ${b.blockHash.slice(0, 24)}...
        </div>
      </div>
    </div>
  `;
}

function updateScopeButtons() {
  document.getElementById('scopeMineBtn').style.borderColor = chainScope === 'mine' ? 'var(--accent)' : '';
  document.getElementById('scopeMineBtn').style.color = chainScope === 'mine' ? 'var(--accent-bright)' : '';
  document.getElementById('scopeAllBtn').style.borderColor = chainScope === 'all' ? 'var(--accent)' : '';
  document.getElementById('scopeAllBtn').style.color = chainScope === 'all' ? 'var(--accent-bright)' : '';
}

async function loadBlockchain() {
  updateScopeButtons();
  try {
    const res = await fetch(`/api/blockchain?scope=${chainScope}`, { headers: authHeaders() });
    const data = await res.json();

    const listEl = document.getElementById('blockList');
    if (!data.blocks || data.blocks.length === 0) {
      listEl.innerHTML = chainScope === 'mine'
        ? '<div class="empty-state">No blocks related to you yet — upload, send, or receive a file to create one.</div>'
        : '<div class="empty-state">No blocks yet — upload or send a file to create the first one.</div>';
      return;
    }
    listEl.innerHTML = data.blocks.map(blockCardHTML).join('');
  } catch (err) {
    document.getElementById('blockList').innerHTML = '<div class="empty-state">Could not load the ledger.</div>';
  }
}

async function validateChainNow() {
  // Chain validation always checks the WHOLE ledger, regardless of the
  // display scope — tamper-evidence is a system-wide property, not a
  // per-user one.
  const statusEl = document.getElementById('chainStatus');
  statusEl.className = 'msg';
  statusEl.textContent = 'Validating...';
  statusEl.style.display = 'block';

  try {
    const res = await fetch('/api/blockchain/validate', { headers: authHeaders() });
    const data = await res.json();

    if (data.valid) {
      statusEl.className = 'msg success';
      statusEl.textContent = `Chain is valid — ${data.blockCount} block(s) system-wide, every hash checks out.`;
    } else {
      statusEl.className = 'msg error';
      statusEl.textContent = `Chain integrity FAILED at block #${data.brokenAt} — ${data.reason}`;
    }
  } catch (err) {
    statusEl.className = 'msg error';
    statusEl.textContent = 'Could not reach the server to validate the chain.';
  }
}

document.getElementById('validateChainBtn').addEventListener('click', validateChainNow);

document.getElementById('scopeMineBtn').addEventListener('click', () => {
  chainScope = 'mine';
  loadBlockchain();
});

document.getElementById('scopeAllBtn').addEventListener('click', () => {
  chainScope = 'all';
  loadBlockchain();
});

// Load the ledger + validate once when the Blockchain tab is first opened.
document.querySelector('.nav-item[data-panel="blockchain"]').addEventListener('click', () => {
  loadBlockchain();
  validateChainNow();
});
