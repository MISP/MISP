<?php
/*
 * The submit of an AI extraction confirmation in the main modal (A4, event
 * or report scope): POST the form by fetch, show a spinner while the module
 * answers, and swap the review screen the controller answers into the same
 * modal, its scripts run like openModal() runs them. A module error comes
 * back as a toast and the form stays usable.
 */
?>
<script>
(function () {
    var form = document.getElementById('PromptForm');
    if (!form) { return; }
    var L = <?= json_encode([
        'waiting' => __('Waiting for the module…'),
        'failed' => __('The extraction failed'),
        'extract' => __('Extract'),
    ], JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
    form.addEventListener('submit', async function (e) {
        e.preventDefault();
        var button = form.querySelector('button[type="submit"]');
        if (button) {
            button.disabled = true;
            button.innerHTML = '<span class="spinner-border spinner-border-sm me-1" role="status"></span>' + L.waiting;
        }
        try {
            var response = await fetch(form.getAttribute('action'), {
                method: 'POST',
                body: new FormData(form),
                headers: { 'X-Requested-With': 'XMLHttpRequest' }
            });
            var type = response.headers.get('content-type') || '';
            if (type.indexOf('application/json') !== -1) {
                var data = await response.json();
                throw new Error(typeof data.errors === 'string' ? data.errors : (data.message || L.failed));
            }
            if (!response.ok) {
                throw new Error(response.statusText || L.failed);
            }
            var html = await response.text();
            var container = document.getElementById('mainModalBody');
            container.innerHTML = html;
            container.querySelectorAll('script:not([type="application/json"])').forEach(function (oldScript) {
                var script = document.createElement('script');
                if (oldScript.src) {
                    script.src = oldScript.src;
                } else {
                    script.textContent = '(function(){\n' + oldScript.textContent + '\n})();';
                }
                document.body.appendChild(script);
                document.body.removeChild(script);
            });
            setModalSize('xl');
        } catch (err) {
            showToast(L.failed + ': ' + err.message, 'danger');
            if (button) {
                button.disabled = false;
                button.innerHTML = '<i class="fas fa-magnifying-glass me-1"></i>' + L.extract;
            }
        }
    });
})();
</script>
