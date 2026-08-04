<?php
$typeLabel = $sighting_type
    ? '<strong class="text-danger">' . __('false-positive') . '</strong>'
    : '<strong class="text-success">' . __('sighting') . '</strong>';
?>

<div class="p-4" style="min-width:320px;">

    <h6 class="fw-semibold mb-3 d-flex align-items-center gap-2">
        <span class="misp-icon misp-icon-sighting misp-hexagone text-primary"></span>
        <?= $sighting_type ? __('Add false-positive sighting') : __('Add sighting') ?>
    </h6>

    <p class="text-muted small mb-4">
        <?= sprintf(__('Add %s sighting for: %s'), $typeLabel, '<code>' . h($tosight) . '</code>') ?>
    </p>

    <div class="d-flex gap-2 justify-content-end">
        <button class="btn btn-sm btn-outline-secondary" onclick="cancelPrompt()">
            <?= __('Cancel') ?>
        </button>
        <button class="btn btn-sm btn-primary" id="quickAddConfirmBtn">
            <i class="fas fa-plus me-1"></i><?= __('Add') ?>
        </button>
    </div>

    <div id="quickAddResult" class="mt-2"></div>
</div>

<script>
document.getElementById('quickAddConfirmBtn').addEventListener('click', async function () {
    var btn = this;
    btn.disabled = true;
    btn.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i><?= __('Saving…') ?>';

    try {
        var r = await fetch(baseurl + '/sightings/add/' + <?= json_encode(h($id)) ?>, {
            method: 'POST',
            headers: {
                'X-Requested-With': 'XMLHttpRequest',
                'Content-Type':     'application/x-www-form-urlencoded',
                'Accept':           'application/json',
                'X-CSRF-Token':     getCsrfToken(),
            },
            body: 'data[Sighting][type]='  + encodeURIComponent(<?= json_encode((int)$sighting_type) ?>)
                + '&data[Sighting][value]=' + encodeURIComponent(<?= json_encode($value) ?>),
        });
        var data = await r.json();
        cancelPrompt();
        if (data.saved) {
            showToast(<?= json_encode(__('Sighting added')) ?>, 'success');
        } else {
            var err = typeof data.errors === 'string'
                ? data.errors
                : <?= json_encode(__('Failed to add sighting')) ?>;
            showToast(err, 'danger');
        }
    } catch (_e) {
        btn.disabled = false;
        btn.innerHTML = '<i class="fas fa-plus me-1"></i><?= __('Add') ?>';
        showToast(<?= json_encode(__('Request failed — please try again')) ?>, 'danger');
    }
});
</script>
