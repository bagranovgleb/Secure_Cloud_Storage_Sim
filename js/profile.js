(function () {
    // ── Avatar file picker ──
    const avatarInput    = document.getElementById('avatar_input');
    const avatarChip     = document.getElementById('avatarChip');
    const avatarChipName = document.getElementById('avatarChipName');
    const avatarSaveBtn  = document.getElementById('avatarSaveBtn');
    const avatarPreview  = document.getElementById('avatarPreview');

    if (avatarInput) {
        avatarInput.addEventListener('change', function () {
            if (!this.files.length) return;
            const file = this.files[0];
            avatarChipName.textContent = file.name;
            avatarChip.style.display = 'inline-flex';
            avatarSaveBtn.disabled = false;

            // Live preview before saving
            const reader = new FileReader();
            reader.onload = e => { avatarPreview.src = e.target.result; };
            reader.readAsDataURL(file);
        });
    }

    // ── Password match hint ──
    const pw1       = document.getElementById('new_password');
    const pw2       = document.getElementById('confirm_password');
    const matchHint = document.getElementById('matchHint');

    function checkMatch() {
        if (!pw2.value) { matchHint.textContent = ''; matchHint.style.color = ''; return; }
        if (pw1.value === pw2.value) {
            matchHint.textContent = '✓ Passwords match';
            matchHint.style.color = 'var(--green)';
        } else {
            matchHint.textContent = '✗ Passwords do not match';
            matchHint.style.color = 'var(--red)';
        }
    }

    if (pw1 && pw2) {
        pw1.addEventListener('input', checkMatch);
        pw2.addEventListener('input', checkMatch);
    }
})();