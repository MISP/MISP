<?php
/**
 * Export modal for a single galaxy cluster to the misp-galaxy JSON format.
 *
 * Available vars: $cluster, $convertedCluster, $galaxy, $galaxy_id, $id.
 */
$type = $cluster['GalaxyCluster']['type'] ?? '';
$json = json_encode($convertedCluster, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
?>

<?= $this->element('genericElementsBS5/Forms/modal_header', [
    'accent' => 'galaxy',
    'eyebrow' => __('Galaxy Clusters'),
    'title' => __('Export to misp-galaxy format'),
    'titleIcon' => 'fas fa-handshake',
    'icon' => 'misp-icon misp-icon-galaxy misp-simple',
]) ?>

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
