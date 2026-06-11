<?php
$isEdit   = $action === 'edit';
$attrData = $attribute['Attribute'] ?? [];

$currentDist = isset($attrData['distribution'])
    ? (int)$attrData['distribution']
    : (int)$initialDistribution;
$currentCat  = $attrData['category'] ?? '';
$currentType = $attrData['type']     ?? '';

$submitId = $isEdit
    ? h($attrData['id'] ?? '')
    : h($event['Event']['id'] ?? '');

/* YYYY-MM-DDTHH:MM:SS for datetime-local picker */
$existingFirstSeen = '';
$existingLastSeen  = '';
if (!empty($attrData['first_seen'])) {
    $existingFirstSeen = h(
        substr(str_replace(' ', 'T', $attrData['first_seen']), 0, 19)
    );
}
if (!empty($attrData['last_seen'])) {
    $existingLastSeen = h(
        substr(str_replace(' ', 'T', $attrData['last_seen']), 0, 19)
    );
}

/* Initial card border colours */
$toIdsChecked        = !empty($attrData['to_ids']);
$disableCorrelChecked = !empty($attrData['disable_correlation']);

$idsBorder    = $toIdsChecked        ? '#ffc107' : '#dee2e6';
$correlBorder = $disableCorrelChecked ? '#dee2e6'  : '#198754';

$idsIconStyle    = $toIdsChecked
    ? 'color:#ffc107;opacity:1;'
    : 'color:#adb5bd;opacity:.7;';
$correlIconStyle = $disableCorrelChecked
    ? 'color:#adb5bd;opacity:.7;'
    : 'color:#198754;opacity:1;';

echo $this->Form->create('Attribute', ['novalidate' => true]);
xdebug_break();
?>

<!-- ── MODAL HEADER ─────────────────────────────────────────── -->
<div class="px-4 pt-3 pb-3 d-flex align-items-center justify-content-between"
     style="background:#97CC040f;
            border-bottom:2px solid var(--attribute);">
    <div>
        <div class="text-attribute text-uppercase fw-semibold mb-1"
             style="font-size:.58rem; letter-spacing:.12em; opacity:.85;">
            <?= __('Attributes') ?>
        </div>
        <h4 class="mb-0 fw-bold d-flex align-items-center gap-2">
            <i class="fas fa-<?= $isEdit ? 'pen-to-square' : 'circle-plus' ?> text-attribute"
               style="font-size:1.25rem;"></i>
            <?= $isEdit ? __('Edit Attribute') : __('Add Attribute') ?>
        </h4>
    </div>
    <span class="misp-icon misp-icon-attribute misp-simple text-attribute" style="font-size:2rem; opacity:.5;"></span>
</div>

<div class="container-fluid px-4 py-4">
    <div class="d-flex flex-column gap-4">

        <!-- ── CATEGORY + TYPE ─────────────────────────────────── -->
        <div class="row g-3">

            <div class="col-md-6">
                <div class="text-attribute fw-bold text-uppercase mb-2"
                     style="font-size:.65rem; letter-spacing:.1em;">
                    <?= __('Category') ?>
                    <span class="badge bg-attribute"
                          style="font-size:.55rem; opacity:.8; font-weight:700;">
                        <?= __('REQUIRED') ?>
                    </span>
                </div>
                <?= $this->Form->select('category', $categories, [
                    'id'    => 'AttributeCategory',
                    'class' => 'form-select',
                    'value' => $currentCat,
                    'empty' => __('(choose one)'),
                ]) ?>
                <div id="notice_category" class="mt-2"
                     style="display:none;overflow:hidden;"></div>
            </div>

            <div class="col-md-6">
                <div class="text-attribute fw-bold text-uppercase mb-2"
                     style="font-size:.65rem; letter-spacing:.1em;">
                    <?= __('Type') ?>
                    <span class="badge bg-attribute"
                          style="font-size:.55rem; opacity:.8; font-weight:700;">
                        <?= __('REQUIRED') ?>
                    </span>
                </div>
                <?= $this->Form->select('type', $types, [
                    'id'       => 'AttributeType',
                    'class'    => 'form-select',
                    'value'    => $currentType,
                    'empty'    => __('(choose category first)'),
                    'disabled' => ($isEdit && !empty($attachment)),
                ]) ?>
                <div id="notice_type" class="mt-2" style="display:none;"></div>
            </div>

        </div>


        <!-- ── VALUE ───────────────────────────────────────────── -->
        <div class="w-100">
            <div class="text-attribute fw-bold text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('Value') ?>
                <span class="badge bg-attribute"
                      style="font-size:.55rem; opacity:.8; font-weight:700;">
                    <?= __('REQUIRED') ?>
                </span>
            </div>
            <?= $this->Form->textarea('value', [
                'id'          => 'AttributeValue',
                'class'       => 'w-100 rounded-2 p-3',
                'style'       => 'background:var(--bs-tertiary-bg, #f8f9fa);'
                    . ' border:1px solid #d8dde3; resize:vertical;'
                    . ' outline:none; font-size:.9rem; min-height:88px;'
                    . ' color:inherit; font-family:inherit;',
                'rows'        => 4,
                'placeholder' => __('Enter the indicator value, hash, IP, domain, or raw observable…')
                    . "\n\n"
                    . __('For batch import, enter one value per line.'),
            ]) ?>
        </div>


        <!-- ── COMMENT ─────────────────────────────────────────── -->
        <div class="w-100">
            <div class="text-attribute fw-bold text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('Contextual Comment') ?>
            </div>
            <?= $this->Form->text('comment', [
                'id'          => 'AttributeComment',
                'class'       => 'w-100 border-0 bg-transparent py-1',
                'style'       => 'border-bottom:1px solid #d8dde3 !important;'
                    . ' outline:none; font-size:.925rem;',
                'placeholder' => __('Add a contextual comment…'),
            ]) ?>
        </div>


        <!-- ── DISTRIBUTION / SHARING GROUP ───────────────────── -->
        <div class="w-100">
            <div class="text-attribute fw-bold text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('Distribution') ?>
            </div>
            <div class="d-flex gap-3">

                <div class="flex-fill">
                    <?= $this->Form->select('distribution', $distributionLevels, [
                        'id'    => 'AttributeDistribution',
                        'class' => 'form-select',
                        'value' => $currentDist,
                    ]) ?>
                </div>

                <div class="flex-fill"
                     id="attr-sg-container"
                     style="<?= $currentDist !== 4 ? 'display:none;' : '' ?>">
                    <?= $this->Form->select('sharing_group_id', $sharingGroups, [
                        'id'    => 'AttributeSharingGroupId',
                        'empty' => __('Select a sharing group…'),
                        'class' => 'form-select',
                    ]) ?>
                </div>

            </div>
        </div>


        <!-- ── ATTRIBUTE SETTINGS ──────────────────────────────── -->
        <div class="w-100">

            <div class="text-attribute fw-bold text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('Settings') ?>
            </div>

            <div class="row g-2 mb-3">

                <?php if (!$isEdit): ?>
                <div class="col-md-4">
                    <label id="card-batch"
                           class="d-flex align-items-center gap-3 rounded-2 p-3
                                  h-100 w-100 user-select-none mb-0"
                           style="cursor:pointer; border:1px solid #dee2e6;">
                        <?= $this->Form->checkbox('batch_import', [
                            'id'    => 'AttributeBatchImport',
                            'class' => 'form-check-input flex-shrink-0',
                            'style' => 'margin-top:0;',
                        ]) ?>
                        <div class="flex-fill">
                            <div class="fw-bold text-uppercase"
                                 style="font-size:.72rem; letter-spacing:.06em; line-height:1.2;">
                                <?= __('Batch Import') ?>
                            </div>
                            <div class="text-muted"
                                 style="font-size:.76rem; margin-top:.2rem; line-height:1.3;">
                                <?= __('One value per line in Value field') ?>
                            </div>
                        </div>
                        <i id="icon-batch"
                           class="fas fa-layer-group"
                           style="font-size:.95rem; color:#adb5bd; opacity:.7;"></i>
                    </label>
                </div>
                <?php endif; ?>

                <div class="<?= $isEdit ? 'col-md-6' : 'col-md-4' ?>">
                    <label id="card-ids"
                           class="d-flex align-items-center gap-3 rounded-2 p-3
                                  h-100 w-100 user-select-none mb-0"
                           style="cursor:pointer; border:1px solid <?= $idsBorder ?>;
                                  transition:border-color .15s;">
                        <?= $this->Form->checkbox('to_ids', [
                            'id'    => 'AttributeToIds',
                            'class' => 'form-check-input flex-shrink-0',
                            'style' => 'margin-top:0;',
                        ]) ?>
                        <div class="flex-fill">
                            <div class="fw-bold text-uppercase"
                                 style="font-size:.72rem; letter-spacing:.06em; line-height:1.2;">
                                <?= __('For IDS') ?>
                            </div>
                            <div class="text-muted"
                                 style="font-size:.76rem; margin-top:.2rem; line-height:1.3;">
                                <?= __('Send to Intrusion Detection System') ?>
                            </div>
                        </div>
                        <i id="icon-ids"
                           class="fas fa-shield-halved"
                           style="font-size:.95rem; <?= $idsIconStyle ?>
                                  transition:color .15s;"></i>
                    </label>
                </div>

                <div class="<?= $isEdit ? 'col-md-6' : 'col-md-4' ?>">
                    <label id="card-correl"
                           class="d-flex align-items-center gap-3 rounded-2 p-3
                                  h-100 w-100 user-select-none mb-0"
                           style="cursor:pointer; border:1px solid <?= $correlBorder ?>;
                                  transition:border-color .15s;">
                        <?= $this->Form->checkbox('disable_correlation', [
                            'id'    => 'AttributeDisableCorrelation',
                            'class' => 'form-check-input flex-shrink-0',
                            'style' => 'margin-top:0;',
                        ]) ?>
                        <div class="flex-fill">
                            <div class="fw-bold text-uppercase"
                                 style="font-size:.72rem; letter-spacing:.06em; line-height:1.2;">
                                <?= __('Disable Correlation') ?>
                            </div>
                            <div class="text-muted"
                                 style="font-size:.76rem; margin-top:.2rem; line-height:1.3;">
                                <?= __('Exclude from correlation engine') ?>
                            </div>
                        </div>
                        <i id="icon-correl"
                           class="fas fa-<?= $disableCorrelChecked ? 'link-slash' : 'link' ?>"
                           style="font-size:.95rem; <?= $correlIconStyle ?>
                                  transition:color .15s;"></i>
                    </label>
                </div>

            </div>

            <div class="d-flex align-items-start gap-2 rounded-2 p-2 small"
                 style="background:rgba(162, 177, 24, 0.05);
                        border:1px solid rgba(174, 177, 24, 0.25);">
                <i class="fas fa-triangle-exclamation text-warning mt-1"></i>
                <div>
                    <strong><?= __('FOR IDS') ?></strong>
                    <?= __('means that this attribute should trigger detection rules and is not for contextual reference.') ?>
                    <br>
                    <strong><?= __('DISABLE CORRELATION') ?></strong>
                    <?= __('prevents MISP from generating correlation graphs for this value.') ?>
                </div>
            </div>

        </div>


        <!-- ── FIRST / LAST SEEN ───────────────────────────────── -->
        <div class="row g-3">

            <div class="col-md-6">
                <div class="text-attribute fw-bold text-uppercase mb-2"
                     style="font-size:.65rem; letter-spacing:.1em;">
                    <?= __('First Seen (UTC)') ?>
                </div>
                <div class="input-group">
                    <span class="input-group-text bg-transparent border-end-0"
                          style="border-color:#d8dde3;">
                        <i class="fas fa-calendar-days text-muted"
                           style="font-size:.82rem;"></i>
                    </span>
                    <input type="datetime-local"
                           step="1"
                           id="attr-first-seen-picker"
                           class="form-control border-start-0"
                           style="border-color:#d8dde3;"
                           value="<?= $existingFirstSeen ?>">
                </div>
            </div>

            <div class="col-md-6">
                <div class="text-attribute fw-bold text-uppercase mb-2"
                     style="font-size:.65rem; letter-spacing:.1em;">
                    <?= __('Last Seen (UTC)') ?>
                </div>
                <div class="input-group">
                    <span class="input-group-text bg-transparent border-end-0"
                          style="border-color:#d8dde3;">
                        <i class="fas fa-calendar-days text-muted"
                           style="font-size:.82rem;"></i>
                    </span>
                    <input type="datetime-local"
                           step="1"
                           id="attr-last-seen-picker"
                           class="form-control border-start-0"
                           style="border-color:#d8dde3;"
                           value="<?= $existingLastSeen ?>">
                </div>
            </div>

        </div>

        <?= $this->Form->hidden('first_seen', [
            'id'    => 'AttributeFirstSeen',
            'value' => str_replace('T', ' ', $existingFirstSeen),
        ]) ?>
        <?= $this->Form->hidden('last_seen', [
            'id'    => 'AttributeLastSeen',
            'value' => str_replace('T', ' ', $existingLastSeen),
        ]) ?>

    </div>


    <!-- ── FOOTER ─────────────────────────────────────────────── -->
    <div class="d-flex justify-content-between align-items-center mt-4 pt-3 flex-wrap gap-2">
        <div class="text-muted" style="font-size:.75rem;">
            <?= __('Event') ?>:
            <strong class="text-body">#<?= h($event['Event']['id'] ?? '') ?></strong>
        </div>
        <div class="d-flex gap-2">
            <button type="button" class="btn btn-outline-secondary btn-sm"
                    data-bs-dismiss="modal">
                <i class="fas fa-times me-1"></i><?= __('Discard') ?>
            </button>
            <?= $this->Form->button(
                '<i class="fas fa-circle-plus me-1"></i> '
                    . ($isEdit ? __('Save Changes') : __('Add Attribute')),
                [
                    'class'       => 'btn btn-attribute btn-sm text-white',
                    'escapeTitle' => false,
                ]
            ) ?>
        </div>
    </div>

</div>

<?= $this->Form->end() ?>

<script>
var non_correlating_types = <?= json_encode($nonCorrelatingTypes) ?>;
var notice_list_triggers  = <?= $notice_list_triggers ?>;
var category_type_mapping = <?= json_encode(array_map(function (array $v) {
    return $v['types'];
}, $categoryDefinitions)) ?>;

var _dist   = <?= (int)$currentDist ?>;
var _isEdit = <?= $isEdit ? 'true' : 'false' ?>;
if (document.readyState !== 'loading') {
    initAttributeForm(_dist, _isEdit);
} else {
    document.addEventListener('DOMContentLoaded', function () {
        initAttributeForm(_dist, _isEdit);
    });
}
</script>