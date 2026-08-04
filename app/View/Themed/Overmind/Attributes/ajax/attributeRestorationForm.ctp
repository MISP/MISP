<?php
$attrId   = (int)($id ?? 0);
$postUrl  = $baseurl . '/attributes/restore/' . $attrId;
?>

<div class="p-4">

    <h6 class="fw-semibold mb-3 d-flex align-items-center gap-2">
        <i class="fas fa-rotate-left text-success"></i>
        <?= __('Restore Attribute #%s', $attrId) ?>
    </h6>

    <p class="text-muted small mb-3">
        <?= __('This attribute will be restored and will become visible again.') ?>
    </p>

    <div class="d-flex justify-content-end gap-2 mt-3">
        <button type="button"
                class="btn btn-outline-secondary btn-sm"
                onclick="bootstrap.Modal.getInstance(document.getElementById('mainModal')).hide()">
            <?= __('Cancel') ?>
        </button>
        <button type="button"
                id="attr-restore-confirm-btn"
                class="btn btn-success btn-sm"
                data-post-url="<?= h($postUrl) ?>"
                data-attr-id="<?= $attrId ?>">
            <i class="fas fa-rotate-left me-1"></i>
            <?= __('Restore') ?>
        </button>
    </div>

</div>

<script>
(function () {
    var btn     = document.getElementById('attr-restore-confirm-btn');
    var postUrl = btn.dataset.postUrl;
    var attrId  = btn.dataset.attrId;
    var _msgOk   = <?= json_encode(__('Attribute restored.')) ?>;
    var _msgFail = <?= json_encode(__('Failed to restore attribute.')) ?>;
    var _msgErr  = <?= json_encode(__('Request failed — please try again.')) ?>;

    btn.addEventListener('click', async function () {
        btn.disabled = true;

        try {
            var r = await fetch(postUrl, {
                method: 'POST',
                headers: {
                    'X-Requested-With': 'XMLHttpRequest',
                    'Accept':           'application/json',
                    'X-CSRF-Token':     getCsrfToken(),
                }
            });
            var data = await r.json();

            if (data.saved) {
                var row = document.querySelector('tr[data-primary-id="' + attrId + '"]');
                if (row) row.remove();

                var modalEl = document.getElementById('mainModal');
                if (modalEl) {
                    var bsModal = bootstrap.Modal.getInstance(modalEl);
                    if (bsModal) bsModal.hide();
                }
                showToast(_msgOk, 'success');
            } else {
                showToast(data.errors || _msgFail, 'danger');
                btn.disabled = false;
            }
        } catch (_e) {
            showToast(_msgErr, 'danger');
            btn.disabled = false;
        }
    });
})();
</script>
