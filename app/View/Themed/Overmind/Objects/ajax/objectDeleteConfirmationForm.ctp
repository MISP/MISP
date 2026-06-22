<?php
$objectId = (int)($id ?? 0);
$hard     = !empty($hard);
$postUrl  = $baseurl . '/objects/delete/' . $objectId . ($hard ? '/true' : '');

$titleText = $hard
    ? __('Permanently delete Object #%s', $objectId)
    : __('Soft-delete Object #%s', $objectId);

$bodyText = $hard
    ? __('This object and all its attributes will be permanently deleted and cannot be recovered.')
    : __('This object will be soft-deleted and can be restored later.');

$btnClass  = $hard ? 'btn-danger'              : 'btn-warning text-dark';
$iconClass = $hard ? 'fa-trash-alt text-danger' : 'fa-trash text-warning';
?>

<div class="p-4">

    <h6 class="fw-semibold mb-3 d-flex align-items-center gap-2">
        <i class="fas <?= $iconClass ?>"></i>
        <?= h($titleText) ?>
    </h6>

    <p class="text-muted small mb-3"><?= h($bodyText) ?></p>

    <?php if ($hard): ?>
    <div class="alert alert-danger d-flex align-items-center gap-2 py-2 mb-3 small">
        <i class="fas fa-triangle-exclamation flex-shrink-0"></i>
        <span><?= __('This action is irreversible.') ?></span>
    </div>
    <?php endif; ?>

    <div class="d-flex justify-content-end gap-2 mt-3">
        <button type="button"
                class="btn btn-outline-secondary btn-sm"
                onclick="bootstrap.Modal.getInstance(document.getElementById('mainModal')).hide()">
            <?= __('Cancel') ?>
        </button>
        <button type="button"
                id="obj-del-confirm-btn"
                class="btn <?= $btnClass ?> btn-sm"
                data-post-url="<?= h($postUrl) ?>"
                data-object-id="<?= $objectId ?>">
            <i class="fas fa-trash me-1"></i>
            <?= $hard ? __('Delete permanently') : __('Soft-delete') ?>
        </button>
    </div>

</div>

<script>
(function () {
    var btn      = document.getElementById('obj-del-confirm-btn');
    var postUrl  = btn.dataset.postUrl;
    var objectId = btn.dataset.objectId;
    var _msgOk   = <?= json_encode($hard ? __('Object deleted permanently.') : __('Object soft-deleted.')) ?>;
    var _msgFail = <?= json_encode($hard ? __('Failed to permanently delete object.') : __('Failed to soft-delete object.')) ?>;
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
                var item = document.querySelector('.accordion-item[data-primary-id="' + objectId + '"]');
                if (item) item.remove();

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
