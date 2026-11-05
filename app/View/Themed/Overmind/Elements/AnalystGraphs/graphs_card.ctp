<?php
/**
 * The workspaces hung off a record (PRD §8.3): each with its creator,
 * distribution and node count, to open, fork or make the active one; and
 * "New workspace" on this record. Also tells the dock which record is on
 * screen, for its own "New workspace" and fork.
 *
 * @var string $targetType Collection, Event or GalaxyCluster
 * @var string $targetUuid
 * @var string $targetLabel
 */
$targetUuid = strtolower($targetUuid);
$this->set('intelGraphPage', ['type' => $targetType, 'uuid' => $targetUuid, 'label' => $targetLabel]);

$canCreate = $this->Acl->canAccess('workspaces', 'addNodes');
$create = null;
if ($canCreate) {
    $sharingGroups = ClassRegistry::init('SharingGroup')->fetchAllAuthorised($me, 'name', 1);
    asort($sharingGroups);
    $levels = [];
    foreach (ClassRegistry::init('Event')->distributionLevels as $level => $name) {
        if ($level < 4 || ($level == 4 && !empty($sharingGroups))) {
            $levels[(int)$level] = $name;
        }
    }
    $create = [
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
    'canFork' => $this->Acl->canAccess('workspaces', 'fork'),
    'create' => $create,
    'distributionLevels' => $this->DistributionLevel->all(),
];
$jsonFlags = JSON_UNESCAPED_SLASHES | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT;
echo $this->element('genericElements/assetLoader', [
    'js' => ['intel-graph-thumb', 'intel-graph-thumbs', 'intel-graph-card'],
    'css' => ['intel-graph-thumbs'],
]);
?>
<div class="card shadow-sm mb-3<?= $canCreate ? '' : ' d-none' ?>" data-ig-graphs-card>
    <script type="application/json" data-ig-card-config><?= json_encode($config, $jsonFlags) ?></script>
    <div class="p-3 border-bottom" data-ig-card-head>
        <div class="d-flex align-items-center gap-2">
            <div class="rounded-2 d-flex align-items-center justify-content-center"
                 style="width:36px;height:36px;background:rgba(var(--bs-analystGraph-rgb),.25);">
                <i class="misp-icon misp-icon-analyst-graph misp-simple text-analystGraph" style="font-size:1rem;"></i>
            </div>
            <div class="me-auto">
                <div class="fw-bold lh-1"><?= __('Workspaces') ?></div>
                <div class="small text-muted mt-1" data-ig-card-count>…</div>
            </div>
            <?php if ($canCreate): ?>
                <button type="button" class="btn btn-sm btn-outline-secondary flex-shrink-0" data-ig-card-new
                        title="<?= __('New workspace on this %s', h($config['targetName'])) ?>">
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

    <?php if ($canCreate):
        $accent = 'analystGraph';
        $formId = 'ig-card-' . substr($targetUuid, 0, 8);
    ?>
        <div class="modal fade" tabindex="-1" aria-hidden="true" aria-labelledby="<?= h($formId) ?>-title" data-ig-card-modal>
            <div class="modal-dialog modal-dialog-centered modal-lg">
                <div class="modal-content border-0">
                    <form novalidate data-required-guard data-ig-card-form>
                        <?= $this->element('genericElementsBS5/Forms/modal_header', [
                            'accent' => $accent,
                            'eyebrow' => __('Workspaces'),
                            'title' => __('New workspace'),
                            'description' => __('It hangs off the %s you are on.', $config['targetName']),
                            'icon' => 'misp-icon misp-icon-analyst-graph misp-simple',
                            'titleId' => $formId . '-title',
                        ]) ?>

                        <div class="container-fluid px-4 py-4">
                            <div class="d-flex flex-column gap-4 px-2">

                                <div class="w-100 ov-form-group">
                                    <?= $this->element('genericElementsBS5/Forms/section_label', [
                                        'accent' => $accent,
                                        'label' => __('Name'),
                                        'required' => true,
                                        'for' => $formId . '-name',
                                    ]) ?>
                                    <input type="text" class="ov-form-line fs-5" id="<?= h($formId) ?>-name" name="name"
                                           maxlength="191" autocomplete="off" required
                                           placeholder="<?= __('Enter a name for this workspace…') ?>"
                                           data-required-msg="<?= __('A workspace needs a name.') ?>">
                                </div>

                                <div class="w-100">
                                    <?= $this->element('genericElementsBS5/Forms/section_label', [
                                        'accent' => $accent,
                                        'label' => __('Description'),
                                        'for' => $formId . '-description',
                                    ]) ?>
                                    <textarea class="form-control" id="<?= h($formId) ?>-description" name="description" rows="3"
                                              style="border-color:var(--misp-field-line, #d8dde3);"
                                              placeholder="<?= __('What this workspace is for') ?>"></textarea>
                                </div>

                                <div class="w-100">
                                    <?= $this->element('genericElementsBS5/Forms/distribution_field', [
                                        'field' => 'Workspace.distribution',
                                        'accent' => $accent,
                                        'levels' => $levels,
                                        'sharingGroups' => $sharingGroups,
                                        'value' => $create['default'],
                                        'id' => $formId . '-distribution',
                                        'sgId' => $formId . '-sharing-group',
                                    ]) ?>
                                </div>

                                <div class="w-100">
                                    <?= $this->element('genericElementsBS5/Forms/section_label', [
                                        'accent' => $accent,
                                        'label' => __('Active workspace'),
                                    ]) ?>
                                    <div class="form-check form-switch">
                                        <input class="form-check-input" type="checkbox" role="switch"
                                               id="<?= h($formId) ?>-activate" name="activate" checked>
                                        <label class="form-check-label" for="<?= h($formId) ?>-activate"><?= __('Make it my active workspace') ?></label>
                                    </div>
                                    <?= $this->element('genericElementsBS5/Forms/field_hint', [
                                        'text' => __('“Add to workspace” on the pages you browse feeds one workspace at a time.'),
                                    ]) ?>
                                </div>

                            </div>

                            <div class="ov-field-error mt-3 px-2" data-ig-card-error hidden>
                                <i class="fas fa-circle-exclamation"></i><span></span>
                            </div>

                            <?= $this->element('genericElementsBS5/Forms/modal_footer', [
                                'accent' => $accent,
                                'meta' => [['label' => ucfirst($config['targetName']), 'value' => $targetLabel]],
                                'submit' => ['label' => __('Create'), 'icon' => 'fas fa-circle-plus'],
                            ]) ?>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    <?php endif; ?>
</div>
