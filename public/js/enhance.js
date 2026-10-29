(function () {
  const savedEmail = localStorage.getItem('dc_email');
  const avatar = document.getElementById('userAvatar');
  if (avatar && savedEmail) {
    avatar.textContent = savedEmail.trim().charAt(0) || '?';
  }

  function wireDropzone(zone) {
    const input = zone.querySelector('input[type="file"]');
    if (!input) return;

    const nameEl = zone.querySelector('.dropzone-filename');

    function sync() {
      const file = input.files && input.files[0];
      if (file) {
        zone.classList.add('has-file');
        if (nameEl) nameEl.textContent = file.name;
      } else {
        zone.classList.remove('has-file');
        if (nameEl) nameEl.textContent = '';
      }
    }

    input.addEventListener('change', sync);

    ['dragenter', 'dragover'].forEach((evt) => {
      zone.addEventListener(evt, (e) => {
        e.preventDefault();
        zone.classList.add('dragover');
      });
    });

    ['dragleave', 'drop', 'dragend'].forEach((evt) => {
      zone.addEventListener(evt, () => zone.classList.remove('dragover'));
    });

    zone.addEventListener('drop', (e) => {
      if (e.dataTransfer && e.dataTransfer.files.length && input.files.length === 0) {
        try {
          const dt = new DataTransfer();
          dt.items.add(e.dataTransfer.files[0]);
          input.files = dt.files;
          sync();
        } catch (err) {
          sync();
        }
      }
      sync();
    });

    const form = zone.closest('form');
    if (form) form.addEventListener('reset', () => setTimeout(sync, 0));
  }

  document.querySelectorAll('.dropzone').forEach(wireDropzone);

  const keyLabel = document.getElementById('keyFileLabel');
  const keyInput = document.getElementById('keyFileInput');
  const keyText = document.getElementById('keyFileNameText');
  if (keyLabel && keyInput && keyText) {
    keyInput.addEventListener('change', () => {
      const file = keyInput.files && keyInput.files[0];
      if (file) {
        keyText.textContent = file.name;
        keyLabel.classList.add('has-file');
      } else {
        keyText.textContent = 'Choose .datachain-key.json';
        keyLabel.classList.remove('has-file');
      }
    });
  }
})();
