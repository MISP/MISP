<?php
/**
 *
 * Read-only galaxy clusters card for a remote event preview.
 *
 */

$galaxies = $data['Galaxy'] ?? [];
if (empty($galaxies)) {
    return;
}
?>

<div class="card shadow-sm mb-3" id="preview-galaxy-card">
    <div class="p-3 border-bottom d-flex align-items-center gap-2">
        <div class="rounded-2 d-flex align-items-center justify-content-center"
             style="width:36px;height:36px;background:#e9d8fc;">
            <span class="misp-icon misp-icon-galaxy misp-simple" style="color:#7C3AED;"></span>
        </div>
        <div class="fw-bold"><?= __('Galaxy Clusters') ?></div>
    </div>
    <div class="p-3">
        <?= $this->element('genericElementsBS5/IndexTable/Fields/galaxy', [
            'row' => ['Galaxy' => $galaxies],
            'field' => ['data_path' => 'Galaxy'],
            'data_path' => 'Galaxy',
        ]); ?>
    </div>
</div>
