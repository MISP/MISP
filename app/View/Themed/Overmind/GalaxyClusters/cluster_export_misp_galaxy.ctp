<?php
/**
 * Export modal for a single galaxy cluster to the misp-galaxy JSON format.
 *
 * Available vars: $cluster, $convertedCluster, $galaxy, $galaxy_id, $id.
 */
$type = $cluster['GalaxyCluster']['type'] ?? '';
$json = json_encode($convertedCluster, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
?>

<!-- ── MODAL HEADER ─────────────────────────────────────────── -->
<div class="px-4 pt-3 pb-3 d-flex align-items-center justify-content-between"
     style="background:rgba(139,92,246,.06); border-bottom:2px solid var(--bs-galaxy);">
    <div>
        <div class="text-galaxy text-uppercase fw-semibold mb-1"
             style="font-size:.58rem; letter-spacing:.12em; opacity:.85;">
            <?= __('Galaxy Clusters') ?>
        </div>
        <h4 class="mb-0 fw-bold d-flex align-items-center gap-2">
            <i class="fas fa-handshake text-galaxy" style="font-size:1.25rem;"></i>
            <?= __('Export to misp-galaxy format') ?>
        </h4>
    </div>
    <span class="misp-icon misp-icon-galaxy misp-simple text-galaxy" style="font-size:2rem; opacity:.5;"></span>
</div>

<!-- ── BODY ─────────────────────────────────────────────────── -->
<div class="p-4">

    <div class="alert alert-info d-flex gap-2 py-2">
        <i class="fas fa-circle-info mt-1"></i>
        <div class="small">
            <?= __('Add this JSON to') ?>
            <code>misp-galaxy/clusters/<?= h($type) ?>.json</code>.
            <?= __("Don't forget to bump the") ?> <code>version</code>
            <?= sprintf(__('at the end of the %s.json file.'), h($type)) ?>
        </div>
    </div>

    <div class="position-relative">
        <button type="button"
                class="btn btn-sm btn-light position-absolute top-0 end-0 m-2"
                title="<?= __('Copy to clipboard') ?>"
                onclick="copyValueToClipboard(document.getElementById('mispGalaxyJson').textContent, '<?= __('JSON copied to clipboard') ?>');">
            <i class="fas fa-copy"></i>
        </button>
        <pre class="bg-light border rounded p-3 mb-0" style="max-height:55vh; overflow:auto;"><code id="mispGalaxyJson"><?= h($json) ?></code></pre>
    </div>

    <div class="d-flex justify-content-end gap-3 mt-4">
        <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">
            <?= __('Close') ?>
        </button>
    </div>

</div>
