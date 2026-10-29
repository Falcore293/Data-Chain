// public/js/forgot-password.js

const emailForm = document.getElementById('emailForm');
const questionsForm = document.getElementById('questionsForm');
const resetForm = document.getElementById('resetForm');
const msgBox = document.getElementById('msg');

let pendingEmail = null;
let resetToken = null;
let lockoutTimer = null;

function showMsg(text, type) {
  msgBox.textContent = text;
  msgBox.className = `msg ${type}`;
}

function startLockoutCountdown(seconds, btn, resetLabel) {
  clearInterval(lockoutTimer);
  btn.disabled = true;
  let remaining = seconds;
  const tick = () => {
    if (remaining <= 0) {
      clearInterval(lockoutTimer);
      btn.disabled = false;
      btn.textContent = resetLabel;
      return;
    }
    btn.textContent = `Locked — wait ${remaining}s`;
    remaining -= 1;
  };
  tick();
  lockoutTimer = setInterval(tick, 1000);
}

emailForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const btn = document.getElementById('emailSubmitBtn');
  btn.disabled = true;
  btn.textContent = 'Looking up...';

  const email = document.getElementById('email').value.trim();

  try {
    const res = await fetch(`/api/auth/forgot-password/questions?email=${encodeURIComponent(email)}`);
    const data = await res.json();

    if (!res.ok) {
      showMsg(data.error || 'Could not find account', 'error');
      if (data.locked && data.retryAfterSeconds) {
        startLockoutCountdown(data.retryAfterSeconds, btn, 'Continue');
      } else {
        btn.disabled = false;
        btn.textContent = 'Continue';
      }
      return;
    }

    pendingEmail = email;
    document.getElementById('questionsFields').innerHTML = data.questions.map((q) => `
      <div class="field">
        <label for="fpAnswer-${q.id}">${q.questionText}</label>
        <input type="text" id="fpAnswer-${q.id}" data-question-id="${q.id}" required>
      </div>
    `).join('');

    emailForm.style.display = 'none';
    questionsForm.style.display = 'block';
    showMsg('', '');
    msgBox.style.display = 'none';
  } catch (err) {
    showMsg('Could not reach the server.', 'error');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Continue';
  }
});

questionsForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  clearInterval(lockoutTimer);
  const btn = document.getElementById('questionsSubmitBtn');
  btn.disabled = true;
  btn.textContent = 'Verifying...';

  const answers = Array.from(document.querySelectorAll('#questionsFields input')).map((input) => ({
    questionId: Number(input.dataset.questionId),
    answer: input.value
  }));

  try {
    const res = await fetch('/api/auth/forgot-password/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: pendingEmail, answers })
    });
    const data = await res.json();

    if (!res.ok) {
      showMsg(data.error || 'Verification failed', 'error');
      if (data.locked && data.retryAfterSeconds) {
        startLockoutCountdown(data.retryAfterSeconds, btn, 'Verify');
      } else {
        btn.disabled = false;
        btn.textContent = 'Verify';
      }
      return;
    }

    resetToken = data.resetToken;
    questionsForm.style.display = 'none';
    resetForm.style.display = 'block';
    msgBox.style.display = 'none';
  } catch (err) {
    showMsg('Could not reach the server.', 'error');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Verify';
  }
});

function downloadPrivateKeyFile(bundle) {
  const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `${bundle.email}.datachain-key.json`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

resetForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const btn = document.getElementById('resetSubmitBtn');
  btn.disabled = true;
  btn.textContent = 'Resetting...';

  const newPassword = document.getElementById('newPassword').value;

  try {
    const res = await fetch('/api/auth/forgot-password/reset', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ resetToken, newPassword })
    });
    const data = await res.json();

    if (!res.ok) {
      showMsg(data.error || 'Reset failed', 'error');
      btn.disabled = false;
      btn.textContent = 'Reset Password';
      return;
    }

    resetForm.style.display = 'none';

    if (data.privateKeyBundle) {
      downloadPrivateKeyFile(data.privateKeyBundle);
      showMsg(`${data.message} Redirecting to login...`, 'success');
      setTimeout(() => {
        window.location.href = 'login.html';
      }, 6000);
    } else {
      showMsg(`${data.message}`, 'success');
    }
    msgBox.style.display = 'block';
  } catch (err) {
    showMsg('Could not reach the server.', 'error');
    btn.disabled = false;
    btn.textContent = 'Reset Password';
  }
});
