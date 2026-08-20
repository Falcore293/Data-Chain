// public/js/login.js

const form = document.getElementById('loginForm');
const twoFaForm = document.getElementById('twoFaForm');
const msgBox = document.getElementById('msg');
const submitBtn = document.getElementById('submitBtn');
const twoFaSubmitBtn = document.getElementById('twoFaSubmitBtn');

let lockoutTimer = null;
let pendingEmail = null;

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
      showMsg('You can try again now.', 'success');
      return;
    }
    btn.textContent = `Locked — wait ${remaining}s`;
    remaining -= 1;
  };
  tick();
  lockoutTimer = setInterval(tick, 1000);
}

function completeLogin(data) {
  // Token + email are needed on every dashboard page. localStorage is
  // fine here — this is a real page served by our own server, not a
  // sandboxed preview.
  localStorage.setItem('dc_token', data.token);
  localStorage.setItem('dc_email', data.email);
  window.location.href = 'dashboard.html';
}

function renderSecurityQuestions(questions) {
  const container = document.getElementById('securityQuestionsFields');
  container.innerHTML = questions.map((q, i) => `
    <div class="field">
      <label for="secAnswer-${q.id}">${q.questionText}</label>
      <input type="text" id="secAnswer-${q.id}" data-question-id="${q.id}" required autofocus="${i === 0}">
    </div>
  `).join('');
}

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  clearInterval(lockoutTimer);
  submitBtn.disabled = true;
  submitBtn.textContent = 'Logging in...';

  const email = document.getElementById('email').value.trim();
  const password = document.getElementById('password').value;

  try {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });
    const data = await res.json();

    if (!res.ok) {
      showMsg(data.error || 'Login failed', 'error');
      if (data.locked && data.retryAfterSeconds) {
        startLockoutCountdown(data.retryAfterSeconds, submitBtn, 'Log In');
      } else {
        submitBtn.disabled = false;
        submitBtn.textContent = 'Log In';
      }
      return;
    }

    if (data.twoFactorRequired) {
      pendingEmail = email;
      form.style.display = 'none';
      renderSecurityQuestions(data.questions);
      twoFaForm.style.display = 'block';
      submitBtn.disabled = false;
      submitBtn.textContent = 'Log In';
      showMsg('Answer your security questions to finish logging in.', 'success');
      return;
    }

    completeLogin(data);
  } catch (err) {
    showMsg('Could not reach the server. Please try again.', 'error');
    submitBtn.disabled = false;
    submitBtn.textContent = 'Log In';
  }
});

twoFaForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  clearInterval(lockoutTimer);
  twoFaSubmitBtn.disabled = true;
  twoFaSubmitBtn.textContent = 'Verifying...';

  const answerInputs = document.querySelectorAll('#securityQuestionsFields input');
  const answers = Array.from(answerInputs).map((input) => ({
    questionId: Number(input.dataset.questionId),
    answer: input.value
  }));

  try {
    const res = await fetch('/api/auth/login/verify-2fa', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: pendingEmail, answers })
    });
    const data = await res.json();

    if (!res.ok) {
      showMsg(data.error || 'Verification failed', 'error');
      if (data.locked && data.retryAfterSeconds) {
        startLockoutCountdown(data.retryAfterSeconds, twoFaSubmitBtn, 'Verify & Log In');
      } else {
        twoFaSubmitBtn.disabled = false;
        twoFaSubmitBtn.textContent = 'Verify & Log In';
      }
      return;
    }

    completeLogin(data);
  } catch (err) {
    showMsg('Could not reach the server. Please try again.', 'error');
    twoFaSubmitBtn.disabled = false;
    twoFaSubmitBtn.textContent = 'Verify & Log In';
  }
});
