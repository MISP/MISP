<?php
$isMass = isset($idArray) && is_array($idArray);
$ids = $isMass ? array_map('intval', $idArray) : [(int)$cluster['id']];
$count = count($ids);

if ($isMass) {
    // Both soft and hard post to deleteSelection; hard is carried in the body.
    $softUrl = h($baseurl . '/galaxy_clusters/deleteSelection');
    $hardUrl = $softUrl;
    $question = $count > 1
        ? sprintf(__('Are you sure you want to delete these %s galaxy clusters?'), $count)
        : __('Are you sure you want to delete the selected galaxy cluster?');
} else {
    $cid = (int)$cluster['id'];
    $softUrl = h($baseurl . '/galaxy_clusters/delete/' . $cid);
    $hardUrl = h($baseurl . '/galaxy_clusters/delete/' . $cid . '/1');
    $question = sprintf(
        __('Are you sure you want to delete Galaxy Cluster %s (%s)?'),
        '<strong>' . h($cluster['value']) . '</strong>',
        h($cluster['id'])
    );
}
$title = $count > 1 ? __('Delete %s Galaxy Clusters', $count) : __('Delete Galaxy Cluster');
?>

<div class="p-4">

    <h6 class="fw-semibold mb-3 d-flex align-items-center gap-2">
        <i class="fas fa-trash"></i>
        <?= h($title) ?>
    </h6>

    <p class="mb-3"><?= $question ?></p>

    <ul class="small text-muted mb-3">
        <li>
            <strong class="text-primary"><?= __('Soft-deleting') ?></strong>
            <?= __('a cluster propagates the deletion to other instances and lets you restore it in the future.') ?>
        </li>
        <li>
            <strong class="text-danger"><?= __('Hard-deleting') ?></strong>
            <?= __('a cluster permanently deletes it and prevents it being created again by blocklisting it.') ?>
            <ul class="mt-1 mb-0">
                <li><?= __('For default clusters, you can restore the cluster at any time by force updating your galaxies.') ?></li>
            </ul>
        </li>
    </ul>

    <!-- Hard-delete warning — hidden until the checkbox is checked -->
    <div class="alert alert-danger d-none d-flex align-items-center gap-2 py-2 mb-3 small" id="cluster-del-hard-alert">
        <i class="fas fa-triangle-exclamation flex-shrink-0"></i>
        <span><?= __('This action is irreversible and blocklists the cluster UUID.') ?></span>
    </div>

    <!-- Hard-delete checkbox (soft-delete by default) -->
    <div class="form-check mb-3">
        <input class="form-check-input" type="checkbox" id="cluster-del-hard-check" autocomplete="off">
        <label class="form-check-label text-muted" style="font-size:.8rem;" for="cluster-del-hard-check">
            <?= __('Permanently delete (hard-delete, cannot be undone)') ?>
        </label>
    </div>

    <div class="d-flex justify-content-end gap-2">
        <button type="button" class="btn btn-outline-secondary btn-sm"
                onclick="bootstrap.Modal.getInstance(document.getElementById('mainModal')).hide()">
            <?= __('Cancel') ?>
        </button>
        <button type="button"
                id="cluster-del-confirm-btn"
                class="btn btn-danger btn-sm"
                data-soft-url="<?= $softUrl ?>"
                data-hard-url="<?= $hardUrl ?>"
                data-is-mass="<?= $isMass ? '1' : '0' ?>"
                data-ids="<?= h(json_encode($ids)) ?>">
            <i class="fas fa-trash me-1"></i>
            <span id="cluster-del-btn-label"><?= __('Soft-delete') ?></span>
        </button>
    </div>

</div>

<script>
(function () {
    var btn     = document.getElementById('cluster-del-confirm-btn');
    var check   = document.getElementById('cluster-del-hard-check');
    var alertEl = document.getElementById('cluster-del-hard-alert');
    var label   = document.getElementById('cluster-del-btn-label');
    if (!btn) return;

    var lblSoft = <?= json_encode(__('Soft-delete')) ?>;
    var lblHard = <?= json_encode(__('Hard-delete')) ?>;
    var msgFail = <?= json_encode(__('Galaxy cluster could not be deleted.')) ?>;
    var msgErr  = <?= json_encode(__('Request failed — please try again.')) ?>;

    var isMass = btn.dataset.isMass === '1';
    var ids    = JSON.parse(btn.dataset.ids);

    check.addEventListener('change', function () {
        alertEl.classList.toggle('d-none', !this.checked);
        label.textContent = this.checked ? lblHard : lblSoft;
    });

    btn.addEventListener('click', async function () {
        btn.disabled = true;
        var hard = check.checked;
        var headers = {
            'X-Requested-With': 'XMLHttpRequest',
            'Accept': 'application/json',
            'X-CSRF-Token': getCsrfToken(),
        };
        var url, body;
        if (isMass) {
            url = btn.dataset.softUrl;
            headers['Content-Type'] = 'application/x-www-form-urlencoded';
            body = 'data[GalaxyCluster][ids]=' + encodeURIComponent(JSON.stringify(ids)) + (hard ? '&data[hard]=1' : '');
        } else {
            url = hard ? btn.dataset.hardUrl : btn.dataset.softUrl;
        }
        try {
            var r = await fetch(url, { method: 'POST', headers: headers, body: body });
            var data = await r.json();
            if (data.saved) {
                var removed = (data.ids && data.ids.length) ? data.ids : ids;
                removed.forEach(function (rid) {
                    var row = document.querySelector('[data-primary-id="' + rid + '"]');
                    if (row) { row.remove(); }
                });
                if (typeof selectedItems !== 'undefined') {
                    removed.forEach(function (rid) { selectedItems.delete(String(rid)); });
                    if (typeof updateMultiSelectToolbar === 'function') { updateMultiSelectToolbar(); }
                }
                var modalEl = document.getElementById('mainModal');
                if (modalEl) {
                    var m = bootstrap.Modal.getInstance(modalEl);
                    if (m) { m.hide(); }
                }
                showToast(data.success || 'Deleted.', 'success');
            } else {
                showToast(data.errors || msgFail, 'danger');
                btn.disabled = false;
            }
        } catch (_e) {
            showToast(msgErr, 'danger');
            btn.disabled = false;
        }
    });
})();
</script>
