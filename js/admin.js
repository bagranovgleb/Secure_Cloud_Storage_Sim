(function () {
    // Update log count badge
    const rows    = document.querySelectorAll('#logRows .log-row');
    const countEl = document.getElementById('logCount');
    if (countEl) countEl.textContent = rows.length + ' events';

    // Scroll to top of log (newest first) on load
    const box = document.getElementById('logBox');
    if (box) box.scrollTop = 0;
})();