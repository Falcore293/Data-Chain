document.querySelectorAll('.pw-toggle').forEach((btn) => {
  btn.addEventListener('click', () => {
    const input = document.getElementById(btn.dataset.target);
    if (!input) return;
    const showing = input.type === 'text';
    input.type = showing ? 'password' : 'text';
    btn.querySelector('.pw-icon-show').style.display = showing ? '' : 'none';
    btn.querySelector('.pw-icon-hide').style.display = showing ? 'none' : '';
    btn.setAttribute('aria-label', showing ? 'Show password' : 'Hide password');
  });
});
