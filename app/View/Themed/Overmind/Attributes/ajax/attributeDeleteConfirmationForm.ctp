<?php
/*
 * Attribute delete confirmation — two entry points:
 *
 *   AttributesController::delete($id)            → single delete
 *     Variables: $id (int), $hard (bool), $event_id (int)
 *     POST target: /attributes/delete/{id}[/true]
 *
 *   AttributesController::deleteSelection($id)   → mass delete
 *     Variables: $idArray (int[]), $hard (bool)
 *     POST target: /attributes/deleteSelection  with Attribute[ids] in body
 */

$isMass  = isset($idArray) && is_array($idArray);
$ids     = $isMass ? $idArray : (isset($id) ? [(int)$id] : []);
$count   = count($ids);
$hard    = !empty($hard);

if ($isMass) {
    $postUrl = $baseurl . '/attributes/deleteSelection';
} else {
    $postUrl = $baseurl . '/attributes/delete/' . h($id) . ($hard ? '/true' : '');
}

$titleText = $hard
    ? ($count === 1 ? __('Permanently delete attribute')        : __('Permanently delete %s attributes', $count))
    : ($count === 1 ? __('Soft-delete attribute')               : __('Soft-delete %s attributes', $count));

$bodyText  = $hard
    ? ($count === 1
        ? __('This attribute will be permanently deleted and cannot be recovered.')
        : __('These %s attributes will be permanently deleted and cannot be recovered.', $count))
    : ($count === 1
        ? __('This attribute will be soft-deleted and can be restored later.')
        : __('These %s attributes will be soft-deleted and can be restored later.', $count));

$btnClass  = $hard ? 'btn-danger'           : 'btn-warning text-dark';
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
                id="attr-del-confirm-btn"
                class="btn <?= $btnClass ?> btn-sm"
                data-post-url="<?= h($postUrl) ?>"
                data-ids="<?= h(json_encode($ids)) ?>"
                data-is-mass="<?= $isMass ? '1' : '0' ?>"
                data-hard="<?= $hard ? '1' : '0' ?>">
            <i class="fas fa-trash me-1"></i>
            <?= $hard ? __('Delete permanently') : __('Soft-delete') ?>
        </button>
    </div>

</div>

<script>
(function () {
    var btn     = document.getElementById('attr-del-confirm-btn');
    var ids     = JSON.parse(btn.dataset.ids);
    var postUrl = btn.dataset.postUrl;
    var isMass  = btn.dataset.isMass === '1';
    var hard    = btn.dataset.hard   === '1';
    var n       = ids.length;

    if (n > 1){
        if (hard) {
            var _msgOk   = <?= json_encode(__('Attributes deleted permanently.')) ?>;
            var _msgFail = <?= json_encode(__('Failed to permanently delete attributes.')) ?>;
        }
        else {
            var _msgOk   = <?= json_encode(__('Attributes soft-deleted.')) ?>;
            var _msgFail = <?= json_encode(__('Failed to soft-delete attributes.')) ?>;
        }
    } else {
        if (hard) {
            var _msgOk   = <?= json_encode(__('Attribute deleted permanently.')) ?>;
            var _msgFail = <?= json_encode(__('Failed to permanently delete attribute.')) ?>;
        }
        else {
            var _msgOk   = <?= json_encode(__('Attribute soft-deleted.')) ?>;
            var _msgFail = <?= json_encode(__('Failed to soft-delete attribute.')) ?>;
        }
    }
    var _msgErr  = <?= json_encode(__('Request failed — please try again.')) ?>;

    btn.addEventListener('click', async function () {
        btn.disabled = true;

        var headers = {
            'X-Requested-With': 'XMLHttpRequest',
            'Accept':           'application/json',
            'X-CSRF-Token':     getCsrfToken(),
        };
        var body;

        if (isMass) {
            headers['Content-Type'] = 'application/x-www-form-urlencoded';
            body = 'data[Attribute][ids]=' + encodeURIComponent(JSON.stringify(ids))
                 + (hard ? '&data[hard]=1' : '');
        }
        /* Single: ID is in the URL, no body needed */

        try {
            var r    = await fetch(postUrl, { method: 'POST', headers: headers, body: body });
            var data = await r.json();

            var deletedIds = (data.ids && data.ids.length) ? data.ids : ids;

            if (data.saved || deletedIds.length > 0) {
                deletedIds.forEach(function (id) {
                    var row = document.querySelector('[data-primary-id="' + id + '"]');
                    if (row) row.remove();
                });
                if (typeof selectedItems !== 'undefined') {
                    deletedIds.forEach(function (id) {
                        selectedItems.delete(String(id));
                    });
                    if (typeof updateMultiSelectToolbar === 'function') {
                        updateMultiSelectToolbar();
                    }
                }
                var modalEl = document.getElementById('mainModal');
                if (modalEl) {
                    var bsModal = bootstrap.Modal.getInstance(modalEl);
                    if (bsModal) bsModal.hide();
                }
                showToast(_msgOk, 'success');
                if (!data.saved && data.errors) {
                    showToast(data.errors, 'warning');
                }
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
