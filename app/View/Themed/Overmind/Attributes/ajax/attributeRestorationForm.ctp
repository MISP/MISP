<?php
/*
 * Restore confirmation for a soft-deleted attribute, from the Deleted filter of
 * an attribute index or an object's attribute menu. Posts through fetch(), like
 * the delete confirmation, then moves the Attributes tab count and reloads the
 * index behind it, which recounts the Deleted filter.
 *
 * Expected: $id (int); $counted (bool, the Attributes tab counts the attribute
 * once it is live again)
 */
$attrId = (int)$id;

echo $this->element('genericElementsBS5/Modals/confirmation_form', [
    'model' => 'Attribute',
    'url' => $baseurl . '/attributes/restore/' . $attrId,
    'hiddenField' => false,
    'eyebrow' => __('Attributes'),
    'accent' => 'success',
    'title' => __('Restore attribute'),
    'message' => __('Restore this attribute?'),
    'bodyHtml' => $this->element('genericElementsBS5/Forms/field_hint', [
        'text' => __('It is listed with the event\'s attributes again, and the event goes back to unpublished.'),
    ]),
    'submitLabel' => __('Restore'),
    'submitIcon' => 'rotate-left',
    'meta' => [['label' => __('Attribute'), 'id' => $attrId]],
]);
?>
<script>
(function () {
    var form = document.querySelector('#mainModalBody #PromptForm');
    if (!form) return;
    var attrId = <?= json_encode((string)$attrId) ?>;
    var counted = <?= !empty($counted) ? 'true' : 'false' ?>;
    var msgDone = <?= json_encode(__('Attribute restored.')) ?>;
    var msgFail = <?= json_encode(__('Attribute could not be restored.')) ?>;

    form.addEventListener('submit', async function (e) {
        e.preventDefault();
        var submit = form.querySelector('[type="submit"]');
        if (submit) { submit.disabled = true; }
        var data = {};
        var ok = false;
        try {
            var r = await fetch(form.action, {
                method: 'POST',
                headers: {
                    'X-Requested-With': 'XMLHttpRequest',
                    'Accept': 'application/json',
                    'X-CSRF-Token': getCsrfToken(),
                },
            });
            data = await r.json().catch(function () { return {}; });
            ok = r.ok;
        } catch (_e) {
            data = {};
        }
        if (!ok || data.saved !== true) {
            showToast(data.errors || data.message || msgFail, 'danger');
            if (submit) { submit.disabled = false; }
            return;
        }

        if (counted) {
            var n = getTabCount('attributes');
            if (n !== null) { setTabCount('attributes', n + 1); }
        }
        if (typeof selectedItems !== 'undefined') {
            selectedItems.delete(attrId);
            updateMultiSelectToolbar();
        }
        var modal = bootstrap.Modal.getInstance(document.getElementById('mainModal'));
        if (modal) { modal.hide(); }
        showToast(msgDone, 'success');
        refreshAfterRowChange({}, [attrId], false);
    });
})();
</script>
