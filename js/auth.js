(function () {
    // ── Card entrance ──
    requestAnimationFrame(() => {
        setTimeout(() => {
            document.getElementById('cardWrap').classList.add('visible');
        }, 60);
    });

    // ── Password show/hide ──
    const pwInput  = document.getElementById('password');
    const pwToggle = document.getElementById('pwToggle');
    const eyeIcon  = document.getElementById('eyeIcon');

    if (pwToggle && pwInput && eyeIcon) {
        const eyeOpen   = '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>';
        const eyeClosed = '<line x1="1" y1="1" x2="23" y2="23"/><path d="M9.88 9.88a3 3 0 004.24 4.24M10.73 5.08A10.43 10.43 0 0112 5c7 0 11 7 11 7a18.5 18.5 0 01-2.16 3.19m-6.72-1.07a3 3 0 01-4.24-4.24M1 1s3.59 4.51 6 6.5"/>';
        let shown = false;
        pwToggle.addEventListener('click', () => {
            shown = !shown;
            pwInput.type = shown ? 'text' : 'password';
            eyeIcon.innerHTML = shown ? eyeClosed : eyeOpen;
        });
    }

    // ── Submit spinner ──
    // Works for both loginForm and registerForm
    const form = document.getElementById('loginForm') || document.getElementById('registerForm');
    if (form) {
        form.addEventListener('submit', function () {
            const btn = document.getElementById('submitBtn');
            if (btn) btn.classList.add('loading');
        });
    }

    // ── Floating particles ──
    for (let i = 0; i < 18; i++) {
        const p = document.createElement('div');
        p.className = 'particle';
        const size     = Math.random() * 3 + 1;
        const left     = Math.random() * 100;
        const duration = Math.random() * 20 + 14;
        const delay    = Math.random() * 20;
        const drift    = (Math.random() - .5) * 120;
        p.style.cssText = `
            width:${size}px; height:${size}px;
            left:${left}vw; bottom:-10px;
            --drift:${drift}px;
            animation-duration:${duration}s;
            animation-delay:-${delay}s;
            opacity:${Math.random() * .4 + .1};
        `;
        document.body.appendChild(p);
    }
})();