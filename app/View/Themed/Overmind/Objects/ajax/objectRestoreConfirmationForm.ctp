<?php
/*
 * Restore confirmation for a soft-deleted object, from its row or card in the
 * Objects tab. Posts through fetch(), like the delete confirmation, then moves
 * the Objects tab count and reloads the index behind it, which recounts the
 * Deleted filter.
 *
 * Expected: $object (the object row)
 */
$objectId = (int)$object['id'];

echo $this->element('genericElementsBS5/Modals/confirmation_form', [
    'model' => 'Object',
    'url' => $baseurl . '/objects/restore/' . $objectId,
    'hiddenField' => false,
    'eyebrow' => __('Objects'),
    'accent' => 'success',
    'title' => __('Restore object'),
    'message' => sprintf(
        __('Restore the object %s?'),
        '<strong>' . h($object['name']) . '</strong>'
    ),
    'escape' => false,
    'bodyHtml' => $this->element('genericElementsBS5/Forms/field_hint', [
        'text' => __('The attributes and references deleted with it come back too; those deleted before it stay deleted. The event goes back to unpublished.'),
    ]),
    'submitLabel' => __('Restore'),
    'submitIcon' => 'rotate-left',
    'meta' => [['label' => __('Object'), 'id' => $objectId]],
]);
?>
<script>
(function () {
    var form = document.querySelector('#mainModalBody #PromptForm');
    if (!form) return;
    var objectId = <?= json_encode((string)$objectId) ?>;
    var msgDone = <?= json_encode(__('Object restored.')) ?>;
    var msgFail = <?= json_encode(__('Object could not be restored.')) ?>;

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

        var n = getTabCount('objects');
        if (n !== null) { setTabCount('objects', n + 1); }
        if (window.objIndexSelection) { window.objIndexSelection.clear([objectId]); }
        var modal = bootstrap.Modal.getInstance(document.getElementById('mainModal'));
        if (modal) { modal.hide(); }
        showToast(msgDone, 'success');
        refreshAfterRowChange({}, [objectId], false);
    });
})();
</script>
