<?php
/*
 * Restore confirmation for a soft-deleted galaxy cluster, from the Clusters
 * tab (Deleted context) or the cluster's own page. Posts through fetch(), like
 * the delete confirmation, and refreshes whichever of the two it came from.
 *
 * Expected: $cluster (the cluster row); $ownPage (bool)
 */
$cid = (int)$cluster['id'];

echo $this->element('genericElementsBS5/Modals/confirmation_form', [
    'model' => 'GalaxyCluster',
    'url' => $baseurl . '/galaxy_clusters/restore/' . $cid,
    'hiddenField' => false,
    'eyebrow' => __('Galaxy clusters'),
    'accent' => 'success',
    'title' => __('Restore galaxy cluster'),
    'message' => sprintf(
        __('Restore the galaxy cluster %s?'),
        '<strong>' . h($cluster['value']) . '</strong>'
    ),
    'escape' => false,
    'bodyHtml' => $this->element('genericElementsBS5/Forms/field_hint', [
        'text' => __('Restoring makes the cluster active again and available for tagging.'),
    ]),
    'submitLabel' => __('Restore'),
    'submitIcon' => 'trash-arrow-up',
    'meta' => [['label' => __('Cluster'), 'id' => $cid]],
]);
?>
<script>
(function () {
    var form = document.querySelector('#mainModalBody #PromptForm');
    if (!form) return;
    var clusterId = <?= json_encode((string)$cid) ?>;
    var ownPage = <?= !empty($ownPage) ? 'true' : 'false' ?>;
    var msgFail = <?= json_encode(__('Galaxy cluster could not be restored.')) ?>;

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

        var n = getTabCount('clusters');
        if (n !== null) { setTabCount('clusters', n + 1); }
        var modal = bootstrap.Modal.getInstance(document.getElementById('mainModal'));
        if (modal) { modal.hide(); }
        showToast(data.success, 'success');
        refreshAfterRowChange({ ownPage: ownPage }, [clusterId], false);
    });
})();
</script>
