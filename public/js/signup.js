// public/js/signup.js

const form = document.getElementById('signupForm');
const msgBox = document.getElementById('msg');
const submitBtn = document.getElementById('submitBtn');

function showMsg(text, type) {
  msgBox.textContent = text;
  msgBox.className = `msg ${type}`;
}

function toggleCustomQuestion(selectId, fieldId) {
  const select = document.getElementById(selectId);
  const field = document.getElementById(fieldId);
  select.addEventListener('change', () => {
    field.style.display = select.value === '__custom__' ? 'block' : 'none';
  });
}
toggleCustomQuestion('secQ1', 'secQ1CustomField');
toggleCustomQuestion('secQ2', 'secQ2CustomField');

// Triggers a browser download of the encrypted private key bundle.
// This JSON file is the ONLY copy of the private key that will ever
// exist - the server discards it after this response.
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

form.addEventListener('submit', async (e) => {
  e.preventDefault();

  const q1Select = document.getElementById('secQ1').value;
  const q2Select = document.getElementById('secQ2').value;
  const question1 = q1Select === '__custom__' ? document.getElementById('secQ1Custom').value.trim() : q1Select;
  const question2 = q2Select === '__custom__' ? document.getElementById('secQ2Custom').value.trim() : q2Select;
  const answer1 = document.getElementById('secA1').value;
  const answer2 = document.getElementById('secA2').value;

  if (!question1 || !question2 || !answer1.trim() || !answer2.trim()) {
    showMsg('Fill in both security questions and answers.', 'error');
    return;
  }
  if (question1 === question2) {
    showMsg('Pick two different security questions.', 'error');
    return;
  }

  submitBtn.disabled = true;
  submitBtn.textContent = 'Creating account...';

  const email = document.getElementById('email').value.trim();
  const password = document.getElementById('password').value;

  try {
    const res = await fetch('/api/auth/signup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email, password,
        questions: [
          { question: question1, answer: answer1 },
          { question: question2, answer: answer2 }
        ]
      })
    });
    const data = await res.json();

    if (!res.ok) {
      showMsg(data.error || 'Signup failed', 'error');
      submitBtn.disabled = false;
      submitBtn.textContent = 'Create Account';
      return;
    }

    // Save the private key file to the user's machine immediately.
    downloadPrivateKeyFile(data.privateKeyBundle);

    showMsg('Account created! Your private key file is downloading now — keep it safe. Redirecting to login...', 'success');

    setTimeout(() => {
      window.location.href = 'login.html';
    }, 2500);
  } catch (err) {
    showMsg('Could not reach the server. Please try again.', 'error');
    submitBtn.disabled = false;
    submitBtn.textContent = 'Create Account';
  }
});
