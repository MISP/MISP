<?php
/**
 * A workspace's own page (PRD §8.2): the explorer at full size. Its
 * editors keep pivoted-in nodes, remove nodes, hide links, draw edges and
 * save; everyone else sees it read-only and may fork it.
 *
 * @var array $graph The summary, target labelled, node_count the viewer's
 * @var bool $canEdit
 * @var bool $canFork
 * @var array $explorer The explorer's write tools and label plan
 * @var array $forkTargets [{type, uuid, label}]
 */
$targetPaths = [
    'Event' => '/events/view/',
    'Collection' => '/collections/view/',
    'GalaxyCluster' => '/galaxy_clusters/view/',
];
$targetTypes = [
    'Event' => __('Event'),
    'Collection' => __('Collection'),
    'GalaxyCluster' => __('Galaxy cluster'),
];
$target = $graph['target'];
$targetType = $targetTypes[$target['type']] ?? $target['type'];
$targetHtml = h($targetType);
if ($target['label'] !== null) {
    $targetHtml .= ' · <a href="' . h($baseurl . $targetPaths[$target['type']] . $target['id']) . '">' . h($target['label']) . '</a>';
}
$description = [
    '<span class="me-3"><i class="fas fa-anchor me-1"></i>' . $targetHtml . '</span>',
    '<span class="me-3"><i class="misp-icon misp-icon-organisation misp-simple me-1"></i>' . h($graph['Orgc']['name'] ?? '') . '</span>',
    $this->element('genericElementsBS5/Badges/distribution', ['distribution' => $graph['distribution']]),
];
if (!empty($graph['forked_from'])) {
    $parentLink = '<a href="' . h($baseurl . '/workspaces/view/' . $graph['forked_from']['uuid']) . '">'
        . h($graph['forked_from']['name']) . '</a>';
    $description[] = '<span class="ms-3" data-ig-forked-from><i class="fas fa-code-fork me-1"></i>'
        . __('Forked from %s', $parentLink) . '</span>';
} elseif (!empty($graph['forked_from_uuid'])) {
    $description[] = '<span class="ms-3"><i class="fas fa-code-fork me-1"></i>' . __('A fork') . '</span>';
}
if (!empty($graph['description'])) {
    $description[] = '<div class="mt-1">' . h($graph['description']) . '</div>';
}

$headerActions = [];
if ($canEdit) {
    $headerActions[] = [
        'type' => 'navigate',
        'label' => __('Settings'),
        'icon' => 'sliders',
        'onClick' => 'igGraphPageSettings',
        'standalone' => true,
    ];
}
if ($canFork) {
    $headerActions[] = [
        'type' => 'navigate',
        'label' => __('Fork'),
        'icon' => 'code-fork',
        'onClick' => 'igGraphPageFork',
        'class' => $canEdit ? 'btn btn-outline-dark' : 'btn btn-primary',
        'standalone' => true,
    ];
}
$this->set('headerTitle', $graph['name']);
$this->set('headerDescription', implode('', $description));
$this->set('headerCount', $graph['node_count']);
$this->set('headerBreadcrumb', [
    ['label' => __('Analyst data'), 'url' => '/analystData/index'],
    ['label' => __('Workspaces'), 'url' => '/analystData/index/Workspace'],
]);
$this->set('headerActions', $headerActions);

$config = [
    'graph' => $graph,
    'canEdit' => $canEdit,
    'canFork' => $canFork,
    'explorer' => $explorer,
    'forkTargets' => $forkTargets,
    'targetTypes' => $targetTypes,
    'targetPaths' => $targetPaths,
    'distributionLevels' => $this->DistributionLevel->all(),
];
$jsonFlags = JSON_UNESCAPED_SLASHES | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT;

// A reader with no navbar slot has no IntelGraph from the layout.
if (empty($intelGraph)) {
    echo $this->element('intel_graph_boot', ['intelGraph' => ['active' => null], 'withDock' => false]);
}
echo $this->element('genericElements/assetLoader', [
    'js' => ['intel-graph-page'],
    'css' => ['intel-graph-page'],
]);
?>
<script type="application/json" id="ig-page-config"><?= json_encode($config, $jsonFlags) ?></script>

<div class="container-fluid pb-3" id="ig-page">
    <?php if (!$canEdit): ?>
        <div class="alert alert-warning d-flex align-items-start gap-2 py-2" role="status" data-ig-page-readonly>
            <i class="fas fa-lock mt-1"></i>
            <div>
                <strong><?= __('%s’s workspace.', h($graph['Orgc']['name'] ?? '')) ?></strong>
                <?= __('Only its organisation can change it: what you move, keep or hide here is not kept.') ?>
                <?php if ($canFork): ?>
                    <?= __('Fork it to work on your own copy.') ?>
                    <button type="button" class="btn btn-sm btn-warning ms-2" onclick="igGraphPageFork()">
                        <i class="fas fa-code-fork me-1"></i><?= __('Fork') ?>
                    </button>
                <?php endif; ?>
            </div>
        </div>
    <?php endif; ?>

    <div class="ig-page-bar d-flex flex-wrap align-items-center gap-2 mb-2" data-ig-page-bar data-tour="graph-bar">
        <div class="ig-page-status me-auto small text-body-secondary" data-ig-page-status role="status" aria-live="polite"></div>
        <div class="dropdown" data-ig-page-size-wrap hidden>
            <button type="button" class="btn btn-sm btn-outline-secondary dropdown-toggle" data-bs-toggle="dropdown"
                    data-bs-auto-close="outside" aria-expanded="false" data-ig-page-size-toggle
                    title="<?= __('The size of the workspace you would save, against what a save can carry') ?>">
                <i class="fas fa-weight-hanging me-1" aria-hidden="true"></i><span data-ig-page-size-label></span>
            </button>
            <div class="dropdown-menu dropdown-menu-end ig-page-size-menu" data-ig-page-size-menu></div>
        </div>
        <button type="button" class="btn btn-sm btn-outline-secondary" data-ig-page-keep hidden
                title="<?= __('Nodes a pivot brought onto the canvas stay out of the workspace until kept') ?>">
            <i class="fas fa-thumbtack me-1"></i><span data-ig-page-keep-label></span>
        </button>
        <div class="dropdown" data-ig-page-hidden-wrap hidden>
            <button type="button" class="btn btn-sm btn-outline-secondary dropdown-toggle" data-bs-toggle="dropdown"
                    data-bs-auto-close="outside" aria-expanded="false" data-ig-page-hidden-toggle>
                <i class="fas fa-eye-slash me-1"></i><span data-ig-page-hidden-label></span>
            </button>
            <div class="dropdown-menu dropdown-menu-end ig-page-hidden-menu" data-ig-page-hidden-menu></div>
        </div>
        <?php if ($canEdit): ?>
            <button type="button" class="btn btn-sm btn-outline-secondary" data-ig-page-discard hidden>
                <?= __('Discard') ?>
            </button>
            <button type="button" class="btn btn-sm btn-primary" data-ig-page-save disabled>
                <i class="fas fa-floppy-disk me-1"></i><?= __('Save') ?>
            </button>
        <?php endif; ?>
    </div>
    <div class="alert alert-danger py-2" data-ig-page-conflict hidden role="alert"></div>

    <div class="card shadow-sm" id="ig-page-card" data-tour="graph-canvas">
        <div class="position-relative">
            <div id="ig-page-loader" class="text-center py-5 text-muted">
                <div class="misp-loader mb-2" role="status"></div>
                <?= __('Building graph…') ?>
            </div>
            <div id="ig-page-graph" style="width:100%;min-height:480px;display:none;"></div>
        </div>
    </div>
</div>

<?php if ($canFork): ?>
<div class="modal fade" id="ig-page-fork" tabindex="-1" aria-labelledby="ig-page-fork-title" aria-hidden="true">
    <div class="modal-dialog">
        <form class="modal-content" data-ig-page-fork-form novalidate>
            <div class="modal-header">
                <h2 class="modal-title fs-5" id="ig-page-fork-title"><i class="fas fa-code-fork me-2"></i><?= __('Fork this workspace') ?></h2>
                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="<?= __('Close') ?>"></button>
            </div>
            <div class="modal-body">
                <p class="small text-body-secondary">
                    <?= __('A copy your organisation owns and edits, holding the nodes you can see. It is shared at your instance’s default for analyst data.') ?>
                </p>
                <label class="form-label fw-semibold" for="ig-page-fork-name"><?= __('Name') ?></label>
                <input type="text" class="form-control mb-3" id="ig-page-fork-name" maxlength="191" required>
                <div class="fw-semibold mb-1"><?= __('Attach it to') ?></div>
                <div data-ig-page-fork-targets></div>
                <div class="invalid-feedback d-block" data-ig-page-fork-error></div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal"><?= __('Cancel') ?></button>
                <button type="submit" class="btn btn-primary"><?= __('Fork') ?></button>
            </div>
        </form>
    </div>
</div>
<?php endif; ?>

<?php if ($canEdit): ?>
<div class="modal fade" id="ig-page-settings" tabindex="-1" aria-labelledby="ig-page-settings-title" aria-hidden="true">
    <div class="modal-dialog">
        <form class="modal-content" data-ig-page-settings-form novalidate>
            <div class="modal-header">
                <h2 class="modal-title fs-5" id="ig-page-settings-title"><i class="fas fa-sliders me-2"></i><?= __('Workspace settings') ?></h2>
                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="<?= __('Close') ?>"></button>
            </div>
            <div class="modal-body">
                <label class="form-label fw-semibold" for="ig-page-settings-name"><?= __('Name') ?></label>
                <input type="text" class="form-control mb-3" id="ig-page-settings-name" maxlength="191" required>
                <label class="form-label fw-semibold" for="ig-page-settings-description"><?= __('Description') ?></label>
                <textarea class="form-control mb-3" id="ig-page-settings-description" rows="3"></textarea>
                <label class="form-label fw-semibold" for="ig-page-settings-distribution"><?= __('Distribution') ?></label>
                <select class="form-select mb-2" id="ig-page-settings-distribution"></select>
                <select class="form-select mb-2" id="ig-page-settings-sg" hidden aria-label="<?= __('Sharing group') ?>"></select>
                <div class="invalid-feedback d-block" data-ig-page-settings-error></div>
            </div>
            <div class="modal-footer justify-content-between">
                <button type="button" class="btn btn-outline-danger" data-ig-page-delete>
                    <i class="fas fa-trash me-1"></i><?= __('Delete workspace') ?>
                </button>
                <div>
                    <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal"><?= __('Cancel') ?></button>
                    <button type="submit" class="btn btn-primary"><?= __('Save') ?></button>
                </div>
            </div>
        </form>
    </div>
</div>
<?php endif; ?>
