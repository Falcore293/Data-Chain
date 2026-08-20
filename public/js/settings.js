// public/js/settings.js

function toggleCustomQuestion(selectId, fieldId) {
  const select = document.getElementById(selectId);
  const field = document.getElementById(fieldId);
  select.addEventListener('change', () => {
    field.style.display = select.value === '__custom__' ? 'block' : 'none';
  });
}
toggleCustomQuestion('setQ1', 'setQ1CustomField');
toggleCustomQuestion('setQ2', 'setQ2CustomField');

// ---------------------------------------------------------------------
// 2FA toggle
// ---------------------------------------------------------------------
document.getElementById('toggle2faBtn').addEventListener('click', async () => {
  const password = document.getElementById('toggle2faPassword').value;
  const btn = document.getElementById('toggle2faBtn');
  const statusEl = document.getElementById('twoFaStatus');

  if (!password) {
    statusEl.className = 'msg error';
    statusEl.textContent = 'Enter your password to change this setting.';
    return;
  }

  const newState = !currentUser.twoFactorEnabled;

  btn.disabled = true;
  btn.textContent = 'Saving...';

  try {
    const res = await fetch('/api/auth/2fa/toggle', {
      method: 'POST',
      headers: { ...authHeaders(), 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled: newState, password })
    });
    const data = await res.json();

    if (!res.ok) {
      statusEl.className = 'msg error';
      statusEl.textContent = data.error || 'Could not update setting';
    } else {
      currentUser.twoFactorEnabled = newState;
      document.getElementById('toggle2faPassword').value = '';
      updateTwoFaUI();
    }
  } catch (err) {
    statusEl.className = 'msg error';
    statusEl.textContent = 'Could not reach the server.';
  } finally {
    btn.disabled = false;
    btn.textContent = 'Toggle';
  }
});

// ---------------------------------------------------------------------
// Change security questions
// ---------------------------------------------------------------------
document.getElementById('changeQuestionsBtn').addEventListener('click', async () => {
  const q1Select = document.getElementById('setQ1').value;
  const q2Select = document.getElementById('setQ2').value;
  const question1 = q1Select === '__custom__' ? document.getElementById('setQ1Custom').value.trim() : q1Select;
  const question2 = q2Select === '__custom__' ? document.getElementById('setQ2Custom').value.trim() : q2Select;
  const answer1 = document.getElementById('setA1').value;
  const answer2 = document.getElementById('setA2').value;
  const password = document.getElementById('changeQPassword').value;
  const msgEl = document.getElementById('changeQuestionsMsg');

  if (!question1 || !question2 || !answer1.trim() || !answer2.trim() || !password) {
    msgEl.className = 'msg error';
    msgEl.style.display = 'block';
    msgEl.textContent = 'Fill in both questions, both answers, and your current password.';
    return;
  }
  if (question1 === question2) {
    msgEl.className = 'msg error';
    msgEl.style.display = 'block';
    msgEl.textContent = 'Pick two different questions.';
    return;
  }

  const btn = document.getElementById('changeQuestionsBtn');
  btn.disabled = true;
  btn.textContent = 'Saving...';

  try {
    const res = await fetch('/api/auth/2fa/questions', {
      method: 'POST',
      headers: { ...authHeaders(), 'Content-Type': 'application/json' },
      body: JSON.stringify({
        questions: [
          { question: question1, answer: answer1 },
          { question: question2, answer: answer2 }
        ],
        password
      })
    });
    const data = await res.json();

    msgEl.className = res.ok ? 'msg success' : 'msg error';
    msgEl.style.display = 'block';
    msgEl.textContent = data.message || data.error;

    if (res.ok) {
      ['setA1', 'setA2', 'setQ1Custom', 'setQ2Custom', 'changeQPassword'].forEach((id) => {
        document.getElementById(id).value = '';
      });
    }
  } catch (err) {
    msgEl.className = 'msg error';
    msgEl.style.display = 'block';
    msgEl.textContent = 'Could not reach the server.';
  } finally {
    btn.disabled = false;
    btn.textContent = 'Update Questions';
  }
});

// ---------------------------------------------------------------------
// Account termination request
// ---------------------------------------------------------------------
document.getElementById('terminateBtn').addEventListener('click', async () => {
  const reason = document.getElementById('terminateReason').value.trim();
  const msgEl = document.getElementById('terminateMsg');

  if (!reason) {
    msgEl.className = 'msg error';
    msgEl.style.display = 'block';
    msgEl.textContent = 'Please state a reason.';
    return;
  }

  if (!confirm('This submits a request to an admin to permanently delete your account. Continue?')) return;

  const btn = document.getElementById('terminateBtn');
  btn.disabled = true;
  btn.textContent = 'Submitting...';

  try {
    const res = await fetch('/api/auth/request-termination', {
      method: 'POST',
      headers: { ...authHeaders(), 'Content-Type': 'application/json' },
      body: JSON.stringify({ reason })
    });
    const data = await res.json();

    msgEl.className = res.ok ? 'msg success' : 'msg error';
    msgEl.style.display = 'block';
    msgEl.textContent = data.message || data.error;

    if (res.ok) {
      document.getElementById('terminateReason').value = '';
    }
  } catch (err) {
    msgEl.className = 'msg error';
    msgEl.style.display = 'block';
    msgEl.textContent = 'Could not reach the server.';
  } finally {
    btn.disabled = false;
    btn.textContent = 'Request Account Termination';
  }
});
