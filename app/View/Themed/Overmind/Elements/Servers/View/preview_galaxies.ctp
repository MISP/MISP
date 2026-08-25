<?php

$galaxies = $data['Galaxy'] ?? [];

$clusterCount = 0;
foreach ($galaxies as $galaxy) {
    $clusterCount += count($galaxy['GalaxyCluster'] ?? []);
}
?>

<div class="card shadow-sm mb-3" id="preview-galaxy-card">
    <div class="p-3 border-bottom d-flex align-items-center gap-2">
        <div class="rounded-2 d-flex align-items-center justify-content-center"
             style="width:36px;height:36px;background:#e9d8fc;">
            <span class="misp-icon misp-icon-galaxy misp-simple" style="color:#7C3AED;"></span>
        </div>
        <div>
            <div class="fw-bold lh-1"><?= __('Galaxy Clusters') ?></div>
            <div class="small text-muted mt-1">
                <?= $clusterCount === 0
                    ? __('No clusters')
                    : $clusterCount . ' ' . __n('cluster', 'clusters', $clusterCount) ?>
            </div>
        </div>
    </div>
    <div class="p-3">
        <?php if (empty($galaxies)): ?>
            <div class="text-center text-muted py-3 small">
                <span class="misp-icon misp-icon-galaxy misp-simple opacity-50 me-1"></span>
                <?= __('This event has no galaxy clusters') ?>
            </div>
        <?php else: ?>
            <?= $this->element('genericElementsBS5/IndexTable/Fields/galaxy', [
                'row' => ['Galaxy' => $galaxies],
                'field' => ['data_path' => 'Galaxy'],
                'data_path' => 'Galaxy',
            ]); ?>
        <?php endif; ?>
    </div>
</div>
