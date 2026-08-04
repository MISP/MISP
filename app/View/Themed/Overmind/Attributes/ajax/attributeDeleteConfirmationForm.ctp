<?php
$isMass = isset($idArray) && is_array($idArray);
$ids    = $isMass ? $idArray : (isset($id) ? [(int)$id] : []);
$count  = count($ids);

$title   = $count === 1 ? __('Delete attribute') : __('Delete %s attributes', $count);

$softBody = $count === 1
    ? __('This attribute will be soft-deleted and can be restored later.')
    : __('These %s attributes will be soft-deleted and can be restored later.', $count);
$hardBody = $count === 1
    ? __('This attribute will be permanently deleted and cannot be recovered.')
    : __('These %s attributes will be permanently deleted and cannot be recovered.', $count);

$softUrl = $isMass
    ? h($baseurl . '/attributes/deleteSelection')
    : h($baseurl . '/attributes/delete/' . (int)$id);

$hardUrl = $isMass
    ? h($baseurl . '/attributes/deleteSelection')
    : h($baseurl . '/attributes/delete/' . (int)$id . '/true');
?>

<div class="p-4">

    <h6 class="fw-semibold mb-3 d-flex align-items-center gap-2">
        <i class="fas fa-trash"></i>
        <?= h($title) ?>
    </h6>

    <p class="text-muted small mb-3" id="attr-del-body"><?= h($softBody) ?></p>

    <!-- Hard-delete warning — hidden until checkbox is checked -->
    <div class="alert alert-danger d-none d-flex align-items-center gap-2 py-2 mb-3 small"
         id="attr-del-hard-alert">
        <i class="fas fa-triangle-exclamation flex-shrink-0"></i>
        <span><?= __('This action is irreversible.') ?></span>
    </div>

    <!-- Hard-delete checkbox -->
    <div class="form-check mb-3">
        <input class="form-check-input" type="checkbox"
               id="attr-del-hard-check" autocomplete="off">
        <label class="form-check-label text-muted"
               style="font-size:.8rem;"
               for="attr-del-hard-check">
            <?= __('Permanently delete (cannot be undone)') ?>
        </label>
    </div>

    <div class="d-flex justify-content-end gap-2 mt-3">
        <button type="button"
                class="btn btn-outline-secondary btn-sm"
                onclick="bootstrap.Modal.getInstance(document.getElementById('mainModal')).hide()">
            <?= __('Cancel') ?>
        </button>
        <button type="button"
                id="attr-del-confirm-btn"
                class="btn btn-danger btn-sm"
                data-soft-url="<?= $softUrl ?>"
                data-hard-url="<?= $hardUrl ?>"
                data-ids="<?= h(json_encode($ids)) ?>"
                data-is-mass="<?= $isMass ? '1' : '0' ?>">
            <i class="fas fa-trash me-1"></i>
            <?= __('Delete') ?>
        </button>
    </div>

</div>

<script>
(function () {
    var btn      = document.getElementById('attr-del-confirm-btn');
    var checkbox = document.getElementById('attr-del-hard-check');
    var bodyEl   = document.getElementById('attr-del-body');
    var alertEl  = document.getElementById('attr-del-hard-alert');

    var softUrl  = btn.dataset.softUrl;
    var hardUrl  = btn.dataset.hardUrl;
    var ids      = JSON.parse(btn.dataset.ids);
    var isMass   = btn.dataset.isMass === '1';
    var n        = ids.length;

    var softBody = <?= json_encode($softBody) ?>;
    var hardBody = <?= json_encode($hardBody) ?>;

    var msgSoftOk   = n > 1 ? <?= json_encode(__('Attributes soft-deleted.'))                 ?> : <?= json_encode(__('Attribute soft-deleted.'))              ?>;
    var msgHardOk   = n > 1 ? <?= json_encode(__('Attributes deleted permanently.'))          ?> : <?= json_encode(__('Attribute deleted permanently.'))       ?>;
    var msgSoftFail = n > 1 ? <?= json_encode(__('Failed to soft-delete attributes.'))        ?> : <?= json_encode(__('Failed to soft-delete attribute.'))     ?>;
    var msgHardFail = n > 1 ? <?= json_encode(__('Failed to permanently delete attributes.')) ?> : <?= json_encode(__('Failed to permanently delete attribute.')) ?>;
    var msgErr      = <?= json_encode(__('Request failed — please try again.')) ?>;

    checkbox.addEventListener('change', function () {
        var hard = this.checked;
        bodyEl.textContent = hard ? hardBody : softBody;
        alertEl.classList.toggle('d-none', !hard);
    });

    btn.addEventListener('click', async function () {
        btn.disabled = true;

        var hard    = checkbox.checked;
        var url     = hard ? hardUrl : softUrl;
        var msgOk   = hard ? msgHardOk   : msgSoftOk;
        var msgFail = hard ? msgHardFail : msgSoftFail;

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

        try {
            var r    = await fetch(url, { method: 'POST', headers: headers, body: body });
            var data = await r.json();

            var deletedIds = (data.ids && data.ids.length) ? data.ids : ids;

            if (data.saved || deletedIds.length > 0) {
                deletedIds.forEach(function (id) {
                    var row = document.querySelector('[data-primary-id="' + id + '"]');
                    if (row) { row.remove(); }
                });
                if (typeof selectedItems !== 'undefined') {
                    deletedIds.forEach(function (id) { selectedItems.delete(String(id)); });
                    if (typeof updateMultiSelectToolbar === 'function') { updateMultiSelectToolbar(); }
                }
                var modalEl = document.getElementById('mainModal');
                if (modalEl) {
                    var bsModal = bootstrap.Modal.getInstance(modalEl);
                    if (bsModal) { bsModal.hide(); }
                }
                showToast(msgOk, 'success');
                if (!data.saved && data.errors) { showToast(data.errors, 'warning'); }
            } else {
                showToast(data.errors || msgFail, 'danger');
                btn.disabled = false;
            }
        } catch (_e) {
            showToast(msgErr, 'danger');
            btn.disabled = false;
        }
    });
}());
</script>
