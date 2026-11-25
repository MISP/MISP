<?php
/**
 * The saved graphs kept on a record, each with its creator, distribution and
 * node count, to open or fork; a graph is made in a Pivot Explorer. On a
 * collection the user may make their workspace, one of their organisation's
 * graphs can lay it out. With $investigations, the card is "In
 * investigations": the collections holding the record, then its saved graphs.
 *
 * @var string $targetType Collection, Event or GalaxyCluster
 * @var string $targetUuid
 * @var string $targetLabel
 * @var bool $canWorkspace The collection can be the user's workspace
 * @var bool $investigations
 * @var string|null $headControl Markup for the card's head
 */
$targetUuid = strtolower($targetUuid);
$investigations = !empty($investigations);
$this->set('intelGraphPage', ['type' => $targetType, 'uuid' => $targetUuid, 'label' => $targetLabel]);

$targetNames = [
    'Event' => __('event'),
    'Collection' => __('collection'),
    'GalaxyCluster' => __('galaxy cluster'),
];
App::uses('Collection', 'Model');
$collectionTypes = Collection::typeLabels();
$config = [
    'baseurl' => $baseurl,
    'target' => ['type' => $targetType, 'uuid' => $targetUuid, 'label' => $targetLabel],
    'targetName' => $targetNames[$targetType] ?? $targetType,
    'investigations' => $investigations,
    'collectionTypes' => $collectionTypes,
    'canFork' => $this->Acl->canAccess('analystGraphs', 'fork'),
    'canWorkspace' => $targetType === 'Collection' && !empty($canWorkspace),
    'canChooseWorkspace' => $this->Acl->canAccess('collections', 'active'),
    'orgUuid' => strtolower($me['Organisation']['uuid'] ?? ''),
    'distributionLevels' => $this->DistributionLevel->all(),
];
$jsonFlags = JSON_UNESCAPED_SLASHES | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT;
echo $this->element('genericElements/assetLoader', [
    'js' => ['intel-graph-thumb', 'intel-graph-thumbs', 'intel-graph-card'],
    'css' => ['intel-graph-thumbs'],
]);
?>
<div class="card shadow-sm mb-3 ig-card" data-ig-graphs-card<?= $investigations ? ' data-ig-investigations' : '' ?>>
    <script type="application/json" data-ig-card-config><?= json_encode($config, $jsonFlags) ?></script>
    <div class="p-3 border-bottom" data-ig-card-head>
        <div class="d-flex align-items-center gap-2">
            <?php if ($investigations): ?>
                <div class="misp-icon-tile rounded-2 d-flex align-items-center justify-content-center flex-shrink-0"
                     style="width:36px;height:36px;--tile:#0d6efd;--tile-bg:#0d6efd40;">
                    <i class="fas fa-folder-tree" style="font-size:1rem;"></i>
                </div>
            <?php else: ?>
                <div class="rounded-2 d-flex align-items-center justify-content-center flex-shrink-0"
                     style="width:36px;height:36px;background:rgba(var(--bs-analystGraph-rgb),.25);">
                    <i class="misp-icon misp-icon-analyst-graph misp-simple text-analystGraph" style="font-size:1rem;"></i>
                </div>
            <?php endif; ?>
            <div class="me-auto" style="min-width:0;">
                <div class="fw-bold lh-1"><?= $investigations ? __('In investigations') : __('Saved graphs') ?></div>
                <div class="small text-muted mt-1" data-ig-card-count>…</div>
            </div>
            <?php if (!empty($headControl)): ?>
                <div class="flex-shrink-0"><?= $headControl ?></div>
            <?php endif; ?>
        </div>
    </div>
    <div data-ig-card-body>
        <div class="text-center py-4 text-muted">
            <div class="misp-loader misp-loader-sm" role="status"></div>
        </div>
    </div>
</div>
