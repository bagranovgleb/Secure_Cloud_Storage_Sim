(function () {
    const zone     = document.getElementById('uploadZone');
    const input    = document.getElementById('cloud_file_trigger');
    const chip     = document.getElementById('fileChip');
    const chipName = document.getElementById('fileChipName');
    const clearBtn = document.getElementById('clearFile');
    const uploadBtn= document.getElementById('uploadBtn');
    const form     = document.getElementById('uploadForm');

    // File selected via input
    input.addEventListener('change', function () {
        if (this.files.length) showChip(this.files[0].name);
        else clearChip();
    });

    // Drag & drop
    zone.addEventListener('dragover', e => { e.preventDefault(); zone.classList.add('drag-over'); });
    zone.addEventListener('dragleave', () => zone.classList.remove('drag-over'));
    zone.addEventListener('drop', e => {
        e.preventDefault();
        zone.classList.remove('drag-over');
        if (e.dataTransfer.files.length) {
            const dt = new DataTransfer();
            dt.items.add(e.dataTransfer.files[0]);
            input.files = dt.files;
            showChip(e.dataTransfer.files[0].name);
        }
    });

    // Clear selection
    clearBtn.addEventListener('click', e => {
        e.stopPropagation();
        input.value = '';
        clearChip();
    });

    function showChip(name) {
        chipName.textContent = name;
        chip.style.display = 'inline-flex';
        uploadBtn.disabled = false;
    }
    function clearChip() {
        chip.style.display = 'none';
        uploadBtn.disabled = true;
    }

    // Animate table rows on load
    document.querySelectorAll('.file-table tbody tr').forEach((row, i) => {
        row.style.opacity = '0';
        row.style.transform = 'translateY(6px)';
        row.style.transition = `opacity .2s ease ${i * 40}ms, transform .2s ease ${i * 40}ms`;
        requestAnimationFrame(() => {
            row.style.opacity = '1';
            row.style.transform = 'translateY(0)';
        });
    });
})();