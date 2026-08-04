<div class="p-4" style="min-width:320px;">

    <h6 class="fw-semibold mb-3 d-flex align-items-center gap-2">
        <i class="fas fa-trash-alt text-danger"></i>
        <?= __('Delete sighting') ?>
    </h6>

    <p class="text-muted small mb-4">
        <?= sprintf(__('Are you sure you want to delete sighting #%s?'), h($id)) ?>
    </p>

    <div class="d-flex gap-2 justify-content-end">
        <button class="btn btn-sm btn-outline-secondary" onclick="cancelPrompt()">
            <?= __('Cancel') ?>
        </button>
        <button class="btn btn-sm btn-danger" id="quickDeleteConfirmBtn">
            <i class="fas fa-trash-alt me-1"></i><?= __('Delete') ?>
        </button>
    </div>

</div>

<script>
document.getElementById('quickDeleteConfirmBtn').addEventListener('click', async function () {
    var btn = this;
    btn.disabled = true;
    btn.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i><?= __('Deleting…') ?>';

    var url = baseurl + '/sightings/quickDelete/'
        + <?= json_encode(h($id)) ?> + '/'
        + encodeURIComponent(<?= json_encode(h($rawId)) ?>) + '/'
        + <?= json_encode(h($context)) ?>;

    try {
        var r = await fetch(url, {
            method: 'POST',
            headers: {
                'X-Requested-With': 'XMLHttpRequest',
                'Accept':           'application/json',
                'X-CSRF-Token':     getCsrfToken(),
            },
        });
        var data = await r.json();
        cancelPrompt();
        if (data.saved) {
            showToast(<?= json_encode(__('Sighting deleted')) ?>, 'success');
            /* Remove the row from the table if advanced modal is open */
            var row = document.querySelector('[data-sighting-id="' + <?= json_encode(h($id)) ?> + '"]');
            if (row) row.remove();
        } else {
            var err = typeof data.errors === 'string'
                ? data.errors
                : <?= json_encode(__('Failed to delete sighting')) ?>;
            showToast(err, 'danger');
        }
    } catch (_e) {
        btn.disabled = false;
        btn.innerHTML = '<i class="fas fa-trash-alt me-1"></i><?= __('Delete') ?>';
        showToast(<?= json_encode(__('Request failed — please try again')) ?>, 'danger');
    }
});
</script>
