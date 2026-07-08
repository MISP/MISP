<?php
$cid = (int)$cluster['id'];
$url = h($baseurl . '/galaxy_clusters/restore/' . $cid);
?>

<div class="p-4">

    <h6 class="fw-semibold mb-3 d-flex align-items-center gap-2">
        <i class="fas fa-trash-arrow-up text-success"></i>
        <?= __('Restore Galaxy Cluster') ?>
    </h6>

    <p class="mb-2">
        <?= sprintf(
            __('Are you sure you want to restore Galaxy Cluster %s (%s)?'),
            '<strong>' . h($cluster['value']) . '</strong>',
            h($cluster['id'])
        ) ?>
    </p>

    <p class="small text-muted mb-3">
        <?= __('Restoring makes the cluster active again and available for tagging.') ?>
    </p>

    <div class="d-flex justify-content-end gap-2">
        <button type="button" class="btn btn-outline-secondary btn-sm"
                onclick="bootstrap.Modal.getInstance(document.getElementById('mainModal')).hide()">
            <?= __('Cancel') ?>
        </button>
        <button type="button"
                id="cluster-restore-btn"
                class="btn btn-success btn-sm"
                data-url="<?= $url ?>"
                data-id="<?= $cid ?>">
            <i class="fas fa-trash-arrow-up me-1"></i>
            <?= __('Restore') ?>
        </button>
    </div>

</div>

<script>
(function () {
    var btn = document.getElementById('cluster-restore-btn');
    if (!btn) return;

    var msgFail = <?= json_encode(__('Galaxy cluster could not be restored.')) ?>;
    var msgErr  = <?= json_encode(__('Request failed — please try again.')) ?>;

    btn.addEventListener('click', async function () {
        btn.disabled = true;
        try {
            var r = await fetch(btn.dataset.url, {
                method: 'POST',
                headers: {
                    'X-Requested-With': 'XMLHttpRequest',
                    'Accept': 'application/json',
                    'X-CSRF-Token': getCsrfToken(),
                }
            });
            var data = await r.json();
            if (data.saved) {
                var row = document.querySelector('[data-primary-id="' + btn.dataset.id + '"]');
                if (row) { row.remove(); }
                var modalEl = document.getElementById('mainModal');
                if (modalEl) {
                    var m = bootstrap.Modal.getInstance(modalEl);
                    if (m) { m.hide(); }
                }
                showToast(data.success || 'Restored.', 'success');
            } else {
                showToast(data.errors || msgFail, 'danger');
                btn.disabled = false;
            }
        } catch (_e) {
            showToast(msgErr, 'danger');
            btn.disabled = false;
        }
    });
})();
</script>
