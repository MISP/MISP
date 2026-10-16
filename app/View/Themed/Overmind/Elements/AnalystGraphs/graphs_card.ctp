<?php
/**
 * The graphs hung off a record (PRD §8.3): each with its creator,
 * distribution and node count, to open, fork or make the active one; and
 * "New graph" on this record. Also tells the dock which record is on screen,
 * for its own "New graph" and fork.
 *
 * @var string $targetType Collection, Event or GalaxyCluster
 * @var string $targetUuid
 * @var string $targetLabel
 */
$targetUuid = strtolower($targetUuid);
$this->set('intelGraphPage', ['type' => $targetType, 'uuid' => $targetUuid, 'label' => $targetLabel]);

$canCreate = $this->Acl->canAccess('analystGraphs', 'addNodes');
$create = null;
if ($canCreate) {
    $levels = [];
    foreach (ClassRegistry::init('Event')->distributionLevels as $level => $name) {
        if ($level <= 4) {
            $levels[] = [(int)$level, $name];
        }
    }
    $sharingGroups = [];
    $authorised = ClassRegistry::init('SharingGroup')->fetchAllAuthorised($me, 'name', 1);
    asort($authorised);
    foreach ($authorised as $id => $name) {
        $sharingGroups[] = [(int)$id, $name];
    }
    $create = [
        'levels' => $levels,
        'sharingGroups' => $sharingGroups,
        'default' => (int)(Configure::read('MISP.default_analyst_data_distribution') ?? 1),
    ];
}
$targetNames = [
    'Event' => __('event'),
    'Collection' => __('collection'),
    'GalaxyCluster' => __('galaxy cluster'),
];
$config = [
    'baseurl' => $baseurl,
    'target' => ['type' => $targetType, 'uuid' => $targetUuid, 'label' => $targetLabel],
    'targetName' => $targetNames[$targetType] ?? $targetType,
    'canCreate' => $canCreate,
    'canFork' => $this->Acl->canAccess('analystGraphs', 'fork'),
    'create' => $create,
    'distributionLevels' => $this->DistributionLevel->all(),
];
$jsonFlags = JSON_UNESCAPED_SLASHES | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT;
echo $this->element('genericElements/assetLoader', [
    'js' => ['intel-graph-thumb', 'intel-graph-thumbs', 'intel-graph-card'],
    'css' => ['intel-graph-thumbs'],
]);
?>
<div class="card shadow-sm mb-3" data-ig-graphs-card>
    <script type="application/json" data-ig-card-config><?= json_encode($config, $jsonFlags) ?></script>
    <div class="p-3 border-bottom">
        <div class="d-flex align-items-center gap-2">
            <div class="rounded-2 d-flex align-items-center justify-content-center"
                 style="width:36px;height:36px;background:rgba(var(--bs-analystGraph-rgb),.25);">
                <i class="misp-icon misp-icon-analyst-graph misp-simple text-analystGraph" style="font-size:1rem;"></i>
            </div>
            <div class="me-auto">
                <div class="fw-bold lh-1"><?= __('Graphs') ?></div>
                <div class="small text-muted mt-1" data-ig-card-count>…</div>
            </div>
            <?php if ($canCreate): ?>
                <button type="button" class="btn btn-sm btn-outline-secondary flex-shrink-0" data-ig-card-new
                        title="<?= __('New graph on this %s', h($config['targetName'])) ?>">
                    <i class="fas fa-plus"></i>
                </button>
            <?php endif; ?>
        </div>
    </div>
    <div data-ig-card-body>
        <div class="text-center py-4 text-muted">
            <div class="misp-loader misp-loader-sm" role="status"></div>
        </div>
    </div>

    <?php if ($canCreate): ?>
        <div class="modal fade" tabindex="-1" aria-hidden="true" data-ig-card-modal>
            <div class="modal-dialog">
                <form class="modal-content" novalidate data-ig-card-form>
                    <div class="modal-header">
                        <h2 class="modal-title fs-5"><i class="misp-icon misp-icon-analyst-graph misp-simple me-2"></i><?= __('New graph') ?></h2>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="<?= __('Close') ?>"></button>
                    </div>
                    <div class="modal-body">
                        <p class="small text-body-secondary">
                            <?= __('On %s, the %s you are on.', '<strong>' . h($targetLabel) . '</strong>', h($config['targetName'])) ?>
                        </p>
                        <label class="form-label fw-semibold" data-ig-for="name"><?= __('Name') ?></label>
                        <input type="text" class="form-control mb-3" name="name" maxlength="191" required>
                        <label class="form-label fw-semibold" data-ig-for="description"><?= __('Description') ?></label>
                        <textarea class="form-control mb-3" name="description" rows="2"></textarea>
                        <label class="form-label fw-semibold" data-ig-for="distribution"><?= __('Distribution') ?></label>
                        <select class="form-select mb-2" name="distribution"></select>
                        <select class="form-select mb-2" name="sharing_group_id" hidden aria-label="<?= __('Sharing group') ?>"></select>
                        <div class="form-check mt-3">
                            <input class="form-check-input" type="checkbox" name="activate" checked>
                            <label class="form-check-label" data-ig-for="activate"><?= __('Make it my active graph: “Add to graph” feeds it') ?></label>
                        </div>
                        <div class="invalid-feedback d-block" data-ig-card-error></div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal"><?= __('Cancel') ?></button>
                        <button type="submit" class="btn btn-primary"><?= __('Create') ?></button>
                    </div>
                </form>
            </div>
        </div>
    <?php endif; ?>
</div>
