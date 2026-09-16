<?php
/**
 * Confirmation for the object index's mass delete — the object counterpart of
 * Attributes/ajax/attributeDeleteConfirmationForm, and deliberately the same
 * shape: soft by default, hard behind a checkbox, one ajax POST, then the rows
 * the server says it deleted are removed in place.
 *
 * The single-object confirmation stays in objectDeleteConfirmationForm: there
 * the caller has already decided soft vs hard from the row's own state.
 *
 * Expected: $idArray (int[]), $hard (bool, initial state of the checkbox)
 */
$ids = array_values(array_map('intval', $idArray));
$count = count($ids);
$hard = !empty($hard);

$title = __n('Delete object', 'Delete %s objects', $count, $count);

$softBody = __n(
    'This object and its attributes will be soft-deleted and can be restored later.',
    'These %s objects and their attributes will be soft-deleted and can be restored later.',
    $count, $count
);
$hardBody = __n(
    'This object and its attributes will be permanently deleted and cannot be recovered.',
    'These %s objects and their attributes will be permanently deleted and cannot be recovered.',
    $count, $count
);
?>

<div class="p-4">

    <h6 class="fw-semibold mb-3 d-flex align-items-center gap-2">
        <i class="fas fa-trash"></i>
        <?= h($title) ?>
    </h6>

    <p class="text-muted small mb-3" id="obj-sel-del-body">
        <?= h($hard ? $hardBody : $softBody) ?>
    </p>

    <div class="alert alert-danger d-flex align-items-center gap-2 py-2 mb-3 small<?= $hard ? '' : ' d-none' ?>"
         id="obj-sel-del-hard-alert">
        <i class="fas fa-triangle-exclamation flex-shrink-0"></i>
        <span><?= __('This action is irreversible.') ?></span>
    </div>

    <div class="form-check mb-3">
        <input class="form-check-input" type="checkbox"
               id="obj-sel-del-hard-check" autocomplete="off"
               <?= $hard ? 'checked' : '' ?>>
        <label class="form-check-label text-muted"
               style="font-size:.8rem;"
               for="obj-sel-del-hard-check">
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
                id="obj-sel-del-confirm-btn"
                class="btn btn-danger btn-sm"
                data-url="<?= h($baseurl . '/objects/deleteSelection') ?>"
                data-ids="<?= h(json_encode($ids)) ?>">
            <i class="fas fa-trash me-1"></i>
            <?= __('Delete') ?>
        </button>
    </div>

</div>

<script>
(function () {
    var btn      = document.getElementById('obj-sel-del-confirm-btn');
    var checkbox = document.getElementById('obj-sel-del-hard-check');
    var bodyEl   = document.getElementById('obj-sel-del-body');
    var alertEl  = document.getElementById('obj-sel-del-hard-alert');

    var url = btn.dataset.url;
    var ids = JSON.parse(btn.dataset.ids);
    var n   = ids.length;

    var softBody = <?= json_encode($softBody) ?>;
    var hardBody = <?= json_encode($hardBody) ?>;

    var msgSoftOk   = n > 1 ? <?= json_encode(__('Objects soft-deleted.'))                 ?> : <?= json_encode(__('Object soft-deleted.'))              ?>;
    var msgHardOk   = n > 1 ? <?= json_encode(__('Objects deleted permanently.'))          ?> : <?= json_encode(__('Object deleted permanently.'))       ?>;
    var msgSoftFail = n > 1 ? <?= json_encode(__('Failed to soft-delete objects.'))        ?> : <?= json_encode(__('Failed to soft-delete object.'))     ?>;
    var msgHardFail = n > 1 ? <?= json_encode(__('Failed to permanently delete objects.')) ?> : <?= json_encode(__('Failed to permanently delete object.')) ?>;
    var msgErr      = <?= json_encode(__('Request failed — please try again.')) ?>;

    checkbox.addEventListener('change', function () {
        bodyEl.textContent = this.checked ? hardBody : softBody;
        alertEl.classList.toggle('d-none', !this.checked);
    });

    btn.addEventListener('click', async function () {
        btn.disabled = true;

        var hard    = checkbox.checked;
        var msgOk   = hard ? msgHardOk   : msgSoftOk;
        var msgFail = hard ? msgHardFail : msgSoftFail;

        try {
            var r = await fetch(url, {
                method: 'POST',
                headers: {
                    'X-Requested-With': 'XMLHttpRequest',
                    'Accept':           'application/json',
                    'X-CSRF-Token':     getCsrfToken(),
                    'Content-Type':     'application/x-www-form-urlencoded',
                },
                body: 'data[Object][ids]=' + encodeURIComponent(JSON.stringify(ids))
                    + (hard ? '&data[hard]=1' : '')
            });
            var data = await r.json();
            var deletedIds = (data.ids && data.ids.length) ? data.ids : (data.saved ? ids : []);

            if (deletedIds.length > 0) {
                // An object id and an attribute id are both plain integers, so
                // the selector has to name the object containers rather than
                // match data-primary-id on its own: .accordion-item is the list
                // view's row, .idx-card the card view's card.
                deletedIds.forEach(function (id) {
                    document
                        .querySelectorAll('.accordion-item[data-primary-id="' + id + '"],'
                                        + ' .idx-card[data-primary-id="' + id + '"]')
                        .forEach(function (el) {
                            (el.closest('.idx-card-col') || el).remove();
                        });
                });
                if (typeof window.objIndexSelection !== 'undefined') {
                    window.objIndexSelection.clear(deletedIds);
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
