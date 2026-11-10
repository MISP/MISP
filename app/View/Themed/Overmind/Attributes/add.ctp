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

/* Initial card border colours */
$toIdsChecked   = !empty($attrData['to_ids']);
$correlChecked  = empty($attrData['disable_correlation']);

$idsBorder    = $toIdsChecked  ? 'var(--misp-tone-yellow-solid, #ffc107)' : 'var(--misp-check-off-line, #dee2e6)';
$correlBorder = $correlChecked ? 'var(--misp-tone-green-solid, #198754)'  : 'var(--misp-check-off-line, #dee2e6)';

$idsIconStyle    = $toIdsChecked
    ? 'color:var(--misp-tone-yellow-solid, #ffc107);opacity:1;'
    : 'color:var(--misp-check-off-icon, #adb5bd);opacity:.7;';
$correlIconStyle = $correlChecked
    ? 'color:var(--misp-tone-green-solid, #198754);opacity:1;'
    : 'color:var(--misp-check-off-icon, #adb5bd);opacity:.7;';

/*
 * An attribute inside an object takes its category and type from the object's
 * template, so neither can be changed here.
 */
$lockedByObject = $isEdit && !empty($objectAttribute);
$lockedMessage  = __('Category and type come from the object template and cannot be changed on an attribute that belongs to an object.');
$typeLocked     = $lockedByObject || ($isEdit && !empty($attachment));

echo $this->Form->create('Attribute', ['novalidate' => true]);
?>

<?= $this->element('genericElementsBS5/Forms/modal_header', [
    'accent' => 'attribute',
    'eyebrow' => __('Attributes'),
    'title' => $isEdit ? __('Edit Attribute') : __('Add Attribute'),
    'icon' => 'misp-icon misp-icon-attribute misp-simple',
    'isEdit' => $isEdit,
]) ?>

<div class="container-fluid px-4 py-4">

    <div class="d-flex flex-column gap-4 px-2">

        <!-- ── CATEGORY + TYPE ─────────────────────────────────── -->
        <div class="row g-3">

            <div class="col-md-6" data-tour="attribute-category">
                <?= $this->element('genericElementsBS5/Forms/section_label', [
                    'accent' => 'attribute',
                    'label' => __('Category'),
                    'required' => true,
                    'for' => 'AttributeCategory',
                ]) ?>
                <?= $this->element('genericElementsBS5/Forms/input_field', [
                    'type' => 'select',
                    'field' => 'category',
                    'id' => 'AttributeCategory',
                    'accent' => 'attribute',
                    'icon' => 'fas fa-layer-group',
                    'options' => $categories,
                    'value' => $currentCat,
                    'empty' => __('Choose a category'),
                    'locked' => $lockedByObject,
                    'lockedTitle' => $lockedMessage,
                ]) ?>
                <div id="notice_category" class="mt-2"
                     style="display:none;overflow:hidden;"></div>
            </div>

            <div class="col-md-6" data-tour="attribute-type">
                <?= $this->element('genericElementsBS5/Forms/section_label', [
                    'accent' => 'attribute',
                    'label' => __('Type'),
                    'required' => true,
                    'for' => 'AttributeType',
                ]) ?>
                <?= $this->element('genericElementsBS5/Forms/input_field', [
                    'type' => 'select',
                    'field' => 'type',
                    'id' => 'AttributeType',
                    'accent' => 'attribute',
                    'icon' => 'fas fa-shapes',
                    'options' => $types,
                    'value' => $currentType,
                    'empty' => __('Choose a category first'),
                    'locked' => $typeLocked,
                    'lockedTitle' => $lockedByObject ? $lockedMessage : null,
                    'inputAttrs' => [
                        'data-placeholder-first' => __('Choose a category first'),
                        'data-placeholder-pick' => __('Choose a type'),
                    ],
                ]) ?>
                <div id="notice_type" class="mt-2" style="display:none;"></div>
            </div>

        </div>


        <!-- ── VALUE ───────────────────────────────────────────── -->
        <div class="w-100" data-tour="attribute-value">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'accent' => 'attribute',
                'label' => __('Value'),
                'required' => true,
                'for' => 'AttributeValue',
            ]) ?>
            <?= $this->element('genericElementsBS5/Forms/input_field', [
                'type' => 'textarea',
                'field' => 'value',
                'id' => 'AttributeValue',
                'accent' => 'attribute',
                'mono' => true,
                'rows' => 3,
                'placeholder' => __('Enter the indicator value, hash, IP, domain, or raw observable…')
                    . "\n\n"
                    . __('For batch import, enter one value per line.'),
                /* initAttributeForm() fills both halves as the value, the type
                 * and the batch switch change. */
                'footHtml' => sprintf(
                    '<span data-value-check></span><span data-value-count></span>'
                        . '<script type="application/json" data-value-labels>%s</script>',
                    json_encode([
                        'checked' => __('Checked as'),
                        'pick' => __('Pick a type to check the value'),
                        'batch' => __('One value per line with Batch import'),
                        'char' => __('1 character'),
                        'chars' => __('%s characters'),
                        'value' => __('1 value'),
                        'values' => __('%s values'),
                    ], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT)
                ),
            ]) ?>
        </div>


        <!-- ── COMMENT ─────────────────────────────────────────── -->
        <div class="w-100">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'accent' => 'attribute',
                'label' => __('Comment'),
                'for' => 'AttributeComment',
            ]) ?>
            <?= $this->element('genericElementsBS5/Forms/input_field', [
                'type' => 'textarea',
                'field' => 'comment',
                'id' => 'AttributeComment',
                'accent' => 'attribute',
                'icon' => 'fas fa-comment',
                'rows' => 2,
                'placeholder' => __('Add a contextual comment…'),
            ]) ?>
        </div>

        <!-- ── DISTRIBUTION / SHARING GROUP ───────────────────── -->
        <div class="w-100">
            <?= $this->element('genericElementsBS5/Forms/distribution_field', [
                'accent' => 'attribute',
                'value' => $currentDistribution ?? 5,
                'id' => 'AttributeDistribution',
                'showSg' => true,
                'sgId' => 'AttributeSharingGroupId',
                'sgEmpty' => __('Select a sharing group…'),
            ]) ?>
        </div>


        <!-- ── ATTRIBUTE SETTINGS ──────────────────────────────── -->
        <div class="w-100">

            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'accent' => 'attribute',
                'label' => __('Settings'),
            ]) ?>

            <div class="row g-2 mb-3">

                <?php if (!$isEdit): ?>
                <div class="col-md-4">
                    <label id="card-batch"
                           class="d-flex align-items-center gap-3 rounded-2 p-3
                                  h-100 w-100 user-select-none mb-0"
                           style="cursor:pointer; border:1px solid var(--misp-check-off-line, #dee2e6);">
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
                           style="font-size:.95rem; color:var(--misp-check-off-icon, #adb5bd); opacity:.7;"></i>
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
                        <?php /* Ticked posts disable_correlation=0, unticked the hidden 1. */ ?>
                        <?= $this->Form->checkbox('disable_correlation', [
                            'id'          => 'AttributeCorrelate',
                            'value'       => '0',
                            'hiddenField' => '1',
                            'checked'     => $correlChecked,
                            'class'       => 'form-check-input flex-shrink-0',
                            'style'       => 'margin-top:0;',
                            'data-locked-title' => __('This type never correlates'),
                        ]) ?>
                        <div class="flex-fill">
                            <div class="fw-bold text-uppercase"
                                 style="font-size:.72rem; letter-spacing:.06em; line-height:1.2;">
                                <?= __('Correlation') ?>
                            </div>
                            <div class="text-muted"
                                 style="font-size:.76rem; margin-top:.2rem; line-height:1.3;">
                                <?= __('Match the value against other events') ?>
                            </div>
                        </div>
                        <i id="icon-correl"
                           class="fas fa-<?= $correlChecked ? 'link' : 'link-slash' ?>"
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
                    <strong><?= __('CORRELATION') ?></strong>
                    <?= __('links this value to the events holding the same value. Untick it to keep the value out of the correlation engine.') ?>
                </div>
            </div>

        </div>


        <!-- ── FIRST / LAST SEEN ───────────────────────────────── -->
        <div class="row g-3">
            <div class="col-md-6">
                <?= $this->element('genericElementsBS5/Forms/section_label', [
                    'accent' => 'attribute',
                    'label' => __('First Seen (UTC)'),
                    'for' => 'AttributeFirstSeenDisplay',
                ]) ?>
                <?= $this->element('genericElementsBS5/Forms/date_field', [
                    'field' => 'first_seen',
                    'id' => 'AttributeFirstSeen',
                    'mode' => 'datetime',
                    'accent' => 'attribute',
                    'value' => $attrData['first_seen'] ?? '',
                ]) ?>
            </div>
            <div class="col-md-6">
                <?= $this->element('genericElementsBS5/Forms/section_label', [
                    'accent' => 'attribute',
                    'label' => __('Last Seen (UTC)'),
                    'for' => 'AttributeLastSeenDisplay',
                ]) ?>
                <?= $this->element('genericElementsBS5/Forms/date_field', [
                    'field' => 'last_seen',
                    'id' => 'AttributeLastSeen',
                    'mode' => 'datetime',
                    'accent' => 'attribute',
                    'value' => $attrData['last_seen'] ?? '',
                    'after' => '#AttributeFirstSeen',
                    'rangeMsg' => __('Last seen cannot be earlier than first seen.'),
                ]) ?>
            </div>
        </div>

    </div>


    <?= $this->element('genericElementsBS5/Forms/modal_footer', [
        'accent' => 'attribute',
        'isEdit' => $isEdit,
        'meta' => [['label' => __('Event'), 'id' => $event['Event']['id'] ?? '']],
        'submit' => [
            'label' => $isEdit ? __('Save Changes') : __('Add Attribute'),
            'icon' => 'fas fa-circle-plus',
        ],
    ]) ?>

</div>

<?= $this->Form->end() ?>

<script>
window.non_correlating_types = <?= json_encode($nonCorrelatingTypes) ?>;
window.notice_list_triggers  = <?= $notice_list_triggers ?>;
window.category_type_mapping = <?= json_encode(array_map(function (array $v) {
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