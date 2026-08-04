<!-- ── MODAL HEADER ─────────────────────────────────────────── -->
<div class="px-4 pt-3 pb-3 d-flex align-items-center justify-content-between"
     style="background:rgba(139,92,246,.06); border-bottom:2px solid var(--bs-galaxy);">
    <div>
        <div class="text-galaxy text-uppercase fw-semibold mb-1"
             style="font-size:.58rem; letter-spacing:.12em; opacity:.85;">
            <?= __('Galaxy Cluster Elements') ?>
        </div>
        <h4 class="mb-0 fw-bold d-flex align-items-center gap-2">
            <i class="fas fa-code text-galaxy" style="font-size:1.25rem;"></i>
            <?= __('Convert JSON into elements') ?>
        </h4>
    </div>
    <span class="misp-icon misp-icon-galaxy misp-simple text-galaxy" style="font-size:2rem; opacity:.5;"></span>
</div>

<!-- ── BODY ─────────────────────────────────────────────────── -->
<div class="p-4">

    <div class="alert alert-warning d-flex gap-2 py-2">
        <i class="fas fa-triangle-exclamation mt-1"></i>
        <div class="small">
            <?= __('The provided JSON is flattened into key/value elements and <u>replaces</u> the current elements of this cluster.') ?>
        </div>
    </div>

    <div class="mb-3">
        <label class="form-label fw-semibold" for="flattenJsonData"><?= __('JSON') ?></label>
        <textarea id="flattenJsonData" class="form-control font-monospace bg-light" rows="12"
                  placeholder='{ "synonyms": [ "..." ], "refs": [ "https://..." ] }'></textarea>
    </div>

    <div class="d-flex justify-content-end gap-3">
        <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">
            <?= __('Cancel') ?>
        </button>
        <button type="button" id="flattenJsonSubmit" class="btn btn-galaxy text-light"
                data-url="<?= h($baseurl . '/galaxy_elements/flattenJson/' . h($clusterId)) ?>">
            <i class="fas fa-check me-1"></i> <?= __('Convert') ?>
        </button>
    </div>

</div>

<script>
(function () {
    var btn = document.getElementById('flattenJsonSubmit');
    var field = document.getElementById('flattenJsonData');
    if (!btn) return;

    var msgFail = <?= json_encode(__('Could not convert JSON.')) ?>;
    var msgErr  = <?= json_encode(__('Request failed — please try again.')) ?>;

    btn.addEventListener('click', async function () {
        var json = field.value.trim();
        if (!json) { field.focus(); return; }
        btn.disabled = true;
        try {
            var body = 'data[GalaxyElement][jsonData]=' + encodeURIComponent(json);
            var r = await fetch(btn.dataset.url, {
                method: 'POST',
                headers: {
                    'X-Requested-With': 'XMLHttpRequest',
                    'Accept': 'application/json',
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'X-CSRF-Token': getCsrfToken(),
                },
                body: body,
            });
            var data = await r.json();
            if (data.saved) {
                var modalEl = document.getElementById('mainModal');
                if (modalEl) {
                    var m = bootstrap.Modal.getInstance(modalEl);
                    if (m) { m.hide(); }
                }
                showToast(data.message || data.success || 'Elements updated.', 'success');
                // Reload the Elements tab in place.
                var container = document.querySelector('.ajax-tab-content[data-url*="galaxy_elements/index"]');
                if (container && container.dataset.url) {
                    fetch(container.dataset.url, { headers: { 'X-Requested-With': 'XMLHttpRequest' } })
                        .then(function (res) { return res.text(); })
                        .then(function (html) {
                            container.innerHTML = html;
                            container.querySelectorAll('script').forEach(function (o) {
                                var s = document.createElement('script');
                                if (o.src) { s.src = o.src; } else { s.textContent = o.textContent; }
                                document.head.appendChild(s);
                                document.head.removeChild(s);
                            });
                        });
                }
            } else {
                showToast(data.errors || data.message || msgFail, 'danger');
                btn.disabled = false;
            }
        } catch (_e) {
            showToast(msgErr, 'danger');
            btn.disabled = false;
        }
    });
})();
</script>
