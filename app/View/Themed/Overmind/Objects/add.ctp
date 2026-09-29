<?php
/*
 * Add or edit an object — two screens in one file, told apart by $template.
 *
 * Without a template this renders the picker alone; with one it renders the
 * form alone. The controller only sends $templateList for the first, because
 * the 378-row list is a quarter of a megabyte the form never reads again.
 */
$templateList = $templateList ?? [];
$hasTemplate  = !empty($template);
$eventId      = h($event['Event']['id']);
$action       = $action ?? 'add';
$isEdit       = $action === 'edit';

$pickerUrl = $baseurl . '/objects/add/' . $eventId;

if (!$hasTemplate):

$metaCategories = [];
foreach ($templateList as $t) {
    $meta = $t['ObjectTemplate']['meta-category'];
    if (!in_array($meta, $metaCategories, true)) {
        $metaCategories[] = $meta;
    }
}
sort($metaCategories);
?>

<?= $this->element('genericElementsBS5/Forms/modal_header', [
    'accent' => 'object',
    'eyebrow' => __('Objects'),
    'title' => __('Add Object'),
    'description' => __('An object groups related attributes under a template that describes what they mean together.'),
    'icon' => 'misp-icon misp-icon-object misp-simple',
]) ?>

<div class="container-fluid px-4 py-4" id="objectTemplatePicker">
    <div class="px-2">
        <div class="mb-3">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'accent' => 'object',
                'label' => __('Meta-category'),
            ]) ?>
            <div class="d-flex flex-wrap gap-2" id="metaCategoryList"
                 role="group" aria-label="<?= __('Filter templates by meta-category') ?>">
                <button type="button"
                        class="btn btn-sm btn-outline-object meta-cat-btn active"
                        data-meta="" aria-pressed="true">
                    <?= __('All') ?>
                    <span class="badge rounded-pill ov-obj-step-badge is-on ms-1"><?= count($templateList) ?></span>
                </button>
                <?php foreach ($metaCategories as $meta): ?>
                    <button type="button"
                            class="btn btn-sm btn-outline-object meta-cat-btn"
                            data-meta="<?= h($meta) ?>" aria-pressed="false">
                        <?= h(Inflector::humanize($meta)) ?>
                        <span class="badge rounded-pill ov-obj-step-badge ms-1"><?= count(array_filter(
                            $templateList,
                            function ($t) use ($meta) { return $t['ObjectTemplate']['meta-category'] === $meta; }
                        )) ?></span>
                    </button>
                <?php endforeach; ?>
            </div>
        </div>

        <?= $this->element('genericElementsBS5/Forms/section_label', [
            'accent' => 'object',
            'label' => __('Template'),
            'required' => true,
            'for' => 'objectTemplateSelect',
        ]) ?>
        <select id="objectTemplateSelect" class="form-select"></select>
        <?= $this->element('genericElementsBS5/Forms/field_hint', [
            'text' => __('Searching matches the name and the description. A meta-category narrows the list without dropping what you already picked.'),
        ]) ?>

        <div id="templateDescPreview" class="alert alert-light border mt-3 d-none"></div>
    </div>

    <?= $this->element('genericElementsBS5/Forms/modal_footer', [
        'accent' => 'object',
        'submit' => [
            'label' => __('Next'),
            'icon' => 'fas fa-arrow-right',
            'id' => 'objNextBtn',
            'type' => 'button',
            'disabled' => true,
        ],
    ]) ?>
</div>

<script type="application/json" id="objectPickerData"><?= json_encode([
    'eventId' => $eventId,
    'formUrl' => $baseurl . '/objects/add/' . $eventId,
    'templates' => array_map(function ($t) {
        return [
            'id' => (string)$t['ObjectTemplate']['id'],
            'name' => Inflector::humanize($t['ObjectTemplate']['name']),
            'meta' => $t['ObjectTemplate']['meta-category'],
            'desc' => $t['ObjectTemplate']['description'],
            'version' => (string)$t['ObjectTemplate']['version'],
        ];
    }, array_values($templateList)),
], JSON_UNESCAPED_SLASHES | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?></script>

<?php
    return;
endif;

/*
 * In edit mode the form posts to edit(), which deltaMerges into the existing
 * object; posting to add() would create a duplicate.
 */
if ($isEdit && !empty($object['Object']['id'])) {
    $formUrl = $baseurl . '/objects/edit/' . h($object['Object']['id']);
    if (!empty($update_template_available)) {
        $formUrl .= '/1';
    }
} else {
    $formUrl = $baseurl . '/objects/add/' . $eventId . '/' . h($template['ObjectTemplate']['id']);
}

echo $this->Form->create('Object', [
    'id'         => 'objectAddForm',
    'url'        => $formUrl,
    'enctype'    => 'multipart/form-data',
    'novalidate' => true,
]);

/*
 * Rows are added client-side, so their fields cannot be in the token hash the
 * server compares against. Unlocking the subtree here — before any row renders,
 * which is what keeps FormHelper from listing them in the first place — is what
 * the legacy flow bought by posting to the unlocked revise_object action.
 */
$this->Form->unlockField('Attribute');

/* The stored ISO strings, which edit() puts on request->data. A datetime-local
 * input only accepts them down to the second. */
$firstSeen = substr((string)($this->request->data['Object']['first_seen'] ?? ''), 0, 19);
$lastSeen  = substr((string)($this->request->data['Object']['last_seen'] ?? ''), 0, 19);
?>

<?= $this->element('genericElementsBS5/Forms/modal_header', [
    'accent' => 'object',
    'eyebrow' => __('Objects'),
    'title' => $isEdit ? __('Edit Object') : __('Add Object'),
    'description' => __('An object groups related attributes under a template that describes what they mean together.'),
    'icon' => 'misp-icon misp-icon-object misp-simple',
    'isEdit' => $isEdit,
]) ?>

<div class="container-fluid px-4 py-4">

    <!-- Chosen template, and the way back to the picker -->
    <div class="ov-obj-template-bar d-flex align-items-center gap-3 flex-wrap px-3 py-2 mb-4 rounded">
        <span class="badge bg-object"><?= $isEdit ? h(__('Template')) : '1' ?></span>
        <span class="fw-semibold"><?= h(Inflector::humanize($template['ObjectTemplate']['name'])) ?></span>
        <span class="badge rounded-pill text-bg-light border text-secondary fw-normal">
            <?= h($template['ObjectTemplate']['meta-category']) ?>
        </span>
        <span class="badge bg-secondary fw-normal">v<?= h($template['ObjectTemplate']['version']) ?></span>

        <?php if (!empty($template['ObjectTemplate']['description'])): ?>
            <span class="ov-obj-template-desc text-muted small text-truncate"
                  title="<?= h($template['ObjectTemplate']['description']) ?>">
                <?= h($template['ObjectTemplate']['description']) ?>
            </span>
        <?php endif; ?>

        <?php if (!$isEdit): ?>
            <button type="button"
                    class="btn btn-sm btn-outline-object ms-auto"
                    id="objChangeTemplateBtn"
                    data-picker-url="<?= h($pickerUrl) ?>">
                <i class="fas fa-rotate-left me-1"></i><?= __('Change template') ?>
            </button>
        <?php endif; ?>
    </div>

    <div class="accordion" id="objectAccordion">

        <!-- ===== OBJECT ===== -->
        <div class="accordion-item border mb-4 rounded shadow-sm">
            <h2 class="accordion-header" id="objHeading2">
                <button class="accordion-button ov-accordion-static rounded"
                        type="button"
                        aria-expanded="true"
                        aria-controls="objCollapse2">
                    <span class="badge bg-object me-2"><?= $isEdit ? '1' : '2' ?></span>
                    <?= __('Object') ?>
                </button>
            </h2>
            <div id="objCollapse2" class="accordion-collapse collapse show" aria-labelledby="objHeading2">
                <div class="accordion-body">

                    <!-- Distribution + sharing group -->
                    <div class="mb-3">
                        <?= $this->element('genericElementsBS5/Forms/distribution_field', [
                            'accent' => 'object',
                            'field' => 'Object.distribution',
                            'id' => 'ObjectDistribution',
                            'value' => $object['Object']['distribution'] ?? $distributionData['initial'],
                            'selectAttrs' => ['class' => 'Object_distribution_select'],
                            'sgId' => 'ObjectSharingGroup',
                            'showSg' => true,
                        ]) ?>
                    </div>

                    <!-- First Seen / Last Seen. A datetime-local input posts the
                         value itself, so nothing here is a hidden field whose
                         value the token seals. -->
                    <div class="row g-3 mb-3">
                        <div class="col-md-6">
                            <?= $this->element('genericElementsBS5/Forms/section_label', [
                                'accent' => 'object',
                                'label' => __('First Seen (UTC)'),
                                'for' => 'ObjectFirstSeen',
                            ]) ?>
                            <div class="input-group">
                                <span class="input-group-text"><i class="fas fa-calendar-days text-muted"></i></span>
                                <?= $this->Form->text('first_seen', [
                                    'type' => 'datetime-local',
                                    'step' => '1',
                                    'id' => 'ObjectFirstSeen',
                                    'class' => 'form-control',
                                    'required' => false,
                                    'value' => $firstSeen,
                                ]) ?>
                            </div>
                        </div>
                        <div class="col-md-6">
                            <?= $this->element('genericElementsBS5/Forms/section_label', [
                                'accent' => 'object',
                                'label' => __('Last Seen (UTC)'),
                                'for' => 'ObjectLastSeen',
                            ]) ?>
                            <div class="input-group">
                                <span class="input-group-text"><i class="fas fa-calendar-days text-muted"></i></span>
                                <?= $this->Form->text('last_seen', [
                                    'type' => 'datetime-local',
                                    'step' => '1',
                                    'id' => 'ObjectLastSeen',
                                    'class' => 'form-control',
                                    'required' => false,
                                    'value' => $lastSeen,
                                ]) ?>
                            </div>
                        </div>
                    </div>

                    <!-- Comment -->
                    <div class="mb-4">
                        <?= $this->element('genericElementsBS5/Forms/section_label', [
                            'accent' => 'object',
                            'label' => __('Comment'),
                            'for' => 'ObjectComment',
                        ]) ?>
                        <?= $this->Form->textarea('Object.comment', [
                            'class'       => 'form-control',
                            'rows'        => 2,
                            'required'    => false,
                            'allowEmpty'  => true,
                            'placeholder' => __('Optional comment…'),
                            'label'       => false,
                            'div'         => false,
                        ]) ?>
                    </div>

                    <?php if (!empty($template['warnings'])): ?>
                        <div class="alert alert-warning mb-4">
                            <strong><?= __('Warning, issues found with the template') ?>:</strong>
                            <?php foreach ($template['warnings'] as $warning): ?>
                                <div><?= h($warning) ?></div>
                            <?php endforeach; ?>
                        </div>
                    <?php endif; ?>

                    <!-- Attributes -->
                    <?php
                    /*
                     * Three groups, and only the first is laid out up front:
                     *   required      - the template will not save without them
                     *   requiredOneOf - at least one of them, picked from a palette
                     *   the rest      - picked from a palette too
                     * A relation nobody has asked for is a <template>, not a hidden
                     * card: it is cloned on demand, so nothing it contains is ever
                     * submitted or reachable by tabbing.
                     */
                    $requiredRelations = $template['ObjectTemplate']['requirements']['required'] ?? [];
                    $oneOfRelations    = $template['ObjectTemplate']['requirements']['requiredOneOf'] ?? [];

                    $groupOf = function ($relation) use ($requiredRelations, $oneOfRelations) {
                        if (in_array($relation, $requiredRelations, true)) {
                            return 'required';
                        }
                        return in_array($relation, $oneOfRelations, true) ? 'oneof' : 'other';
                    };

                    $upfront = ['required' => [], 'oneof' => [], 'other' => []];
                    $palette = ['oneof' => [], 'other' => []];
                    $sources = [];
                    $lastRow = -1;

                    foreach ($template['ObjectTemplateElement'] as $k => $element) {
                        $lastRow = $k;
                        $relation = $element['object_relation'];
                        $group = $groupOf($relation);
                        // A value means the row is already part of the object (edit mode,
                        // or an add the server rejected), so it stays laid out.
                        $hasValue = isset($element['value']) && $element['value'] !== '';

                        if ($group === 'required' || $hasValue) {
                            $upfront[$group][$k] = $element;
                        }
                        // Every relation gets a clone source, required ones included:
                        // a repeatable required relation still has to be able to grow,
                        // which is what splitting a pasted list relies on.
                        if (!isset($sources[$relation])) {
                            $sources[$relation] = ['k' => $k, 'element' => $element];
                        }
                        // Only the two open groups get a palette button.
                        if ($group !== 'required' && !isset($palette[$group][$relation])) {
                            $palette[$group][$relation] = $element;
                        }
                    }
                    ?>

                    <?= $this->element('genericElementsBS5/Forms/section_label', [
                        'accent' => 'object',
                        'label' => __('Attributes'),
                    ]) ?>

                    <div id="editTable" class="mb-4">

                        <?php if (!empty($upfront['required'])): ?>
                            <div class="ov-obj-group-label">
                                <i class="fas fa-asterisk text-danger me-1"></i>
                                <?= __('Required by this template') ?>
                            </div>
                            <div class="ov-obj-cards" data-group="required">
                                <?php foreach ($upfront['required'] as $k => $element): ?>
                                    <?= $this->element('Objects/object_add_attributes', [
                                        'element' => $element,
                                        'k' => $k,
                                        'action' => $action,
                                        'enabledRows' => $enabledRows,
                                        'removable' => false,
                                    ]) ?>
                                <?php endforeach; ?>
                            </div>
                        <?php endif; ?>

                        <?php foreach (['oneof', 'other'] as $group): ?>
                            <?php if (empty($palette[$group]) && empty($upfront[$group])) { continue; } ?>

                            <?php if (!empty($palette[$group])): ?>
                                <div class="card ov-obj-palette mb-3" data-palette="<?= h($group) ?>">
                                    <div class="card-header ov-obj-palette-header">
                                        <?php if ($group === 'oneof'): ?>
                                            <i class="fas fa-circle-half-stroke text-warning me-1"></i>
                                            <?= __('At least one of these is required') ?>
                                        <?php else: ?>
                                            <i class="fas fa-plus text-object me-1"></i>
                                            <?= __('Other attributes') ?>
                                        <?php endif; ?>
                                        <span class="text-muted fw-normal ms-1">
                                            <?= __('— click to add') ?>
                                        </span>
                                    </div>
                                    <div class="card-body d-flex flex-wrap gap-2 py-2">
                                        <?php foreach ($palette[$group] as $relation => $element): ?>
                                            <?php
                                            $multiple = !empty($element['multiple']);
                                            // A single-occurrence relation already laid out has
                                            // nothing left to add.
                                            $used = !$multiple && isset($upfront[$group])
                                                && !empty(array_filter(
                                                    $upfront[$group],
                                                    function ($e) use ($relation) {
                                                        return $e['object_relation'] === $relation;
                                                    }
                                                ));
                                            ?>
                                            <button type="button"
                                                    class="btn btn-sm ov-obj-pick"
                                                    data-add-relation="<?= h($relation) ?>"
                                                    data-multiple="<?= $multiple ? '1' : '0' ?>"
                                                    data-target="<?= h($group) ?>"
                                                    title="<?= h($element['description'] ?? $relation) ?>"
                                                    <?= $used ? 'disabled' : '' ?>>
                                                <i class="fas fa-plus"></i>
                                                <span><?= h(Inflector::humanize($relation)) ?></span>
                                                <span class="ov-obj-pick-type"><?= h($element['type']) ?></span>
                                                <?php if ($multiple): ?>
                                                    <i class="fas fa-layer-group ov-obj-pick-multi"
                                                       title="<?= __('Can be added more than once') ?>"></i>
                                                <?php endif; ?>
                                            </button>
                                        <?php endforeach; ?>
                                    </div>
                                </div>
                            <?php endif; ?>

                            <div class="ov-obj-cards" data-group="<?= h($group) ?>">
                                <?php foreach ($upfront[$group] as $k => $element): ?>
                                    <?= $this->element('Objects/object_add_attributes', [
                                        'element' => $element,
                                        'k' => $k,
                                        'action' => $action,
                                        'enabledRows' => $enabledRows,
                                        'removable' => true,
                                    ]) ?>
                                <?php endforeach; ?>
                            </div>
                        <?php endforeach; ?>

                        <?php foreach ($sources as $relation => $source): ?>
                            <template class="ov-obj-row-source" data-relation="<?= h($relation) ?>">
                                <?= $this->element('Objects/object_add_attributes', [
                                    'element' => $source['element'],
                                    'k' => $source['k'],
                                    'action' => $action,
                                    'enabledRows' => [],
                                    'removable' => true,
                                    'blank' => true,
                                ]) ?>
                            </template>
                        <?php endforeach; ?>

                    </div>

                    <div id="last-row" class="d-none" data-last-row="<?= h($lastRow) ?>"></div>

                    <div class="d-flex justify-content-end">
                        <button type="button" class="btn btn-object" id="objReviewBtn">
                            <i class="fas fa-eye me-1"></i><?= __('Review') ?>
                            <i class="fas fa-chevron-down ms-1"></i>
                        </button>
                    </div>

                </div>
            </div>
        </div>

        <!-- ===== REVIEW ===== -->
        <div class="accordion-item border mb-2 rounded shadow-sm">
            <h2 class="accordion-header" id="objHeading3">
                <button class="accordion-button ov-accordion-static collapsed rounded"
                        type="button"
                        aria-expanded="false"
                        aria-controls="objCollapse3">
                    <span class="badge bg-object me-2"><?= $isEdit ? '2' : '3' ?></span>
                    <?= __('Review') ?>
                </button>
            </h2>
            <div id="objCollapse3" class="accordion-collapse collapse" aria-labelledby="objHeading3">
                <div class="accordion-body p-3">
                    <div id="objSimilarObjects" class="mb-3"></div>
                    <div id="objReviewBody">
                        <div class="text-center text-muted py-4 fst-italic">
                            <i class="fas fa-eye d-block mb-2 opacity-25 fa-2x"></i>
                            <?= __('Use "Review" above to check the object before submitting.') ?>
                        </div>
                    </div>
                    <div class="d-flex justify-content-start">
                        <button type="button" class="btn btn-outline-secondary btn-sm" id="objPrevBtn3">
                            <i class="fas fa-chevron-up me-1"></i><?= __('Back to the object') ?>
                        </button>
                    </div>
                </div>
            </div>
        </div>

    </div><!-- /accordion -->

    <div id="objFormError" class="alert alert-danger mt-3 mb-0 d-none" role="alert"></div>

    <?= $this->element('genericElementsBS5/Forms/modal_footer', [
        'accent' => 'object',
        'isEdit' => $isEdit,
        'metaHtml' => '<span id="objWarningMessage" class="text-danger fw-bold d-none">'
            . '<i class="fas fa-triangle-exclamation me-1"></i>'
            . h(__('You are about to share data of a classified nature. Make sure that you are authorised to.'))
            . '</span>',
        'submit' => [
            'label' => $isEdit ? __('Save Changes') : __('Add Object'),
            'icon' => 'fas fa-check',
            'id' => 'submitButton',
            'type' => 'submit',
        ],
    ]) ?>

</div>

<script type="application/json" id="objectFormData"><?= json_encode([
    'eventId' => $eventId,
    'isEdit' => $isEdit,
    'pickerUrl' => $pickerUrl,
    'similarUrl' => $baseurl . '/objects/similar_objects/' . $eventId
        . '/' . $template['ObjectTemplate']['id'],
    'distributionLevels' => (object)$distributionData['levels'],
    'template' => [
        'id' => (string)$template['ObjectTemplate']['id'],
        'name' => Inflector::humanize($template['ObjectTemplate']['name']),
        'meta' => $template['ObjectTemplate']['meta-category'],
        'version' => (string)$template['ObjectTemplate']['version'],
        'required' => array_values($template['ObjectTemplate']['requirements']['required'] ?? []),
        'requiredOneOf' => array_values($template['ObjectTemplate']['requirements']['requiredOneOf'] ?? []),
    ],
], JSON_UNESCAPED_SLASHES | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?></script>

<?= $this->Form->end() ?>
