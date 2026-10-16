<?php
$clusters = [];
foreach ($galaxies as $galaxy) {
    foreach ($galaxy['GalaxyCluster'] ?? [] as $cluster) {
        $clusters[] = $cluster + [
            'galaxy' => $galaxy['name'] ?? '',
            'galaxy_id' => $galaxy['id'] ?? null,
            'icon' => $galaxy['icon'] ?? 'meteor',
        ];
    }
}
$totalClusters = count($clusters);
?>

<div data-galaxy-count="<?= $totalClusters ?>"
     data-galaxy-count-label="<?= h($totalClusters === 1 ? __('cluster') : __('clusters')) ?>">

<?php if (empty($clusters)): ?>

    <div class="d-flex flex-column align-items-center justify-content-center
                text-muted py-4" data-galaxy-empty>
        <span class="misp-icon misp-icon-galaxy misp-hexagone mb-2 opacity-50" style="font-size:2em;"></span>
        <p class="mb-0 small fw-semibold">
            <?= __('No galaxy clusters associated with this event.') ?>
        </p>
    </div>

<?php else: ?>

    <div class="p-3" data-galaxy-list>
        <?= $this->TagChip->clusters($clusters, [
            'prefix' => function (array $cluster) {
                return $this->element('Events/View/extension_origin', [
                    'event_id' => $cluster['event_id'] ?? null,
                    'compact' => true,
                    'only_foreign' => true,
                ]);
            },
        ]) ?>
    </div>

    <div class="d-none text-center text-muted py-3 small"
         data-galaxy-noresult>
        <i class="fas fa-search me-1 opacity-50"></i>
        <?= __('No galaxy clusters match your search.') ?>
    </div>

<?php endif; ?>

</div>
