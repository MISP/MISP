<?php
// $templateList holds every available object template for the add-form picker.
$templateList = $templateList ?? [];
$hasTemplate = !empty($template);
$eventId     = h($event['Event']['id']);
$templateId  = $hasTemplate ? h($template['ObjectTemplate']['id']) : '';

// Build meta-category list from templateList
$metaCategories = [];
foreach ($templateList as $t) {
    $meta = $t['ObjectTemplate']['meta-category'];
    if (!in_array($meta, $metaCategories, true)) {
        $metaCategories[] = $meta;
    }
}
sort($metaCategories);

// Pre-selected category (from template already chosen)
$selectedMeta = $hasTemplate ? $template['ObjectTemplate']['meta-category'] : '';

// In edit mode the form must POST to edit() (which deltaMerges into the existing object); posting to add() creates a duplicate. 
if (!$hasTemplate) {
    $formUrl = '#';
} elseif (($action ?? 'add') === 'edit' && !empty($object['Object']['id'])) {
    $formUrl = $baseurl . '/objects/edit/' . h($object['Object']['id']);
    if (!empty($update_template_available)) {
        $formUrl .= '/1';
    }
} else {
    $formUrl = $baseurl . '/objects/add/' . $eventId . '/' . $templateId;
}

echo $this->Form->create('Object', [
    'id'       => 'objectAddForm',
    'url'      => $formUrl,
    'enctype'  => 'multipart/form-data',
    'novalidate' => true,
]);

// $k may be undefined when template has no elements — define safe fallback
$k = -1;
?>

<!-- ── PAGE HEADER ──────────────────────────────────────────── -->
<div class="px-4 pt-3 pb-3 d-flex align-items-center justify-content-between"
     style="background:rgba(82,73,72,.06);
            border-bottom:2px solid var(--bs-object);">
    <div>
        <div class="text-object text-uppercase fw-semibold mb-1"
             style="font-size:.58rem; letter-spacing:.12em; opacity:.85;">
            <?= __('Objects') ?>
        </div>
        <h4 class="mb-0 fw-bold d-flex align-items-center gap-2">
            <i class="fas fa-circle-plus text-object" style="font-size:1.25rem;"></i>
            <?= __('Add Object') ?>
        </h4>
    </div>
    <span class="misp-icon misp-icon-object misp-simple text-object"
          style="font-size:2rem; opacity:.5;"></span>
</div>

<!-- ── ACCORDION WIZARD ─────────────────────────────────────── -->
<div class="container-fluid px-4 py-3">
    <div class="accordion" id="objectAccordion">

        <!-- ===== STEP 1 : TEMPLATE SELECTION ===== -->
        <div class="accordion-item border mb-2 rounded shadow-sm">
            <h2 class="accordion-header" id="objHeading1">
                <button class="accordion-button <?= $hasTemplate ? 'collapsed' : '' ?> rounded"
                        type="button"
                        aria-expanded="<?= $hasTemplate ? 'false' : 'true' ?>"
                        aria-controls="objCollapse1"
                        style="cursor:default; pointer-events:none;">
                    <span class="badge bg-object me-2">1</span>
                    <?= __('Template') ?>
                    <?php if ($hasTemplate): ?>
                        <span class="ms-2 badge text-bg-success fw-normal">
                            <?= h($template['ObjectTemplate']['meta-category']) ?>
                            /
                            <?= h(Inflector::humanize($template['ObjectTemplate']['name'])) ?>
                        </span>
                    <?php endif; ?>
                </button>
            </h2>
            <div id="objCollapse1"
                 class="accordion-collapse collapse <?= !$hasTemplate ? 'show' : '' ?>"
                 aria-labelledby="objHeading1"
                 data-bs-parent="#objectAccordion">
                <div class="accordion-body">

                    <!-- Meta-category badges -->
                    <div class="mb-3">
                        <div class="text-object fw-bold text-uppercase mb-2"
                             style="font-size:.65rem; letter-spacing:.1em;">
                            <?= __('Meta-category') ?>
                        </div>
                        <div class="d-flex flex-wrap gap-2" id="metaCategoryList">
                            <button type="button"
                                    class="btn btn-sm btn-outline-object meta-cat-btn <?= !$hasTemplate ? 'active' : '' ?>"
                                    data-meta="">
                                <?= __('All') ?>
                            </button>
                            <?php foreach ($metaCategories as $meta): ?>
                                <button type="button"
                                        class="btn btn-sm btn-outline-object meta-cat-btn <?= ($hasTemplate && $selectedMeta === $meta) ? 'active' : '' ?>"
                                        data-meta="<?= h($meta) ?>">
                                    <?= h(Inflector::humanize($meta)) ?>
                                </button>
                            <?php endforeach; ?>
                        </div>
                    </div>

                    <!-- Template picker (TomSelect) -->
                    <div class="mb-3">
                        <div class="text-object fw-bold text-uppercase mb-2"
                             style="font-size:.65rem; letter-spacing:.1em;">
                            <?= __('Template') ?>
                        </div>
                        <select id="objectTemplateSelect" class="form-select">
                            <option value=""><?= __('-- Select a template --') ?></option>
                            <?php foreach ($templateList as $t): ?>
                                <option value="<?= h($t['ObjectTemplate']['id']) ?>"
                                        data-meta="<?= h($t['ObjectTemplate']['meta-category']) ?>"
                                        data-desc="<?= h($t['ObjectTemplate']['description']) ?>"
                                        data-version="<?= h($t['ObjectTemplate']['version']) ?>"
                                        <?= ($hasTemplate && $t['ObjectTemplate']['id'] == $template['ObjectTemplate']['id']) ? 'selected' : '' ?>>
                                    <?= h(Inflector::humanize($t['ObjectTemplate']['name'])) ?>
                                    (<?= h($t['ObjectTemplate']['meta-category']) ?>)
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>

                    <!-- Description preview -->
                    <div id="templateDescPreview"
                         class="alert alert-light border mb-3 <?= !$hasTemplate ? 'd-none' : '' ?>">
                        <?php if ($hasTemplate): ?>
                            <strong>
                                <?= h(Inflector::humanize($template['ObjectTemplate']['name'])) ?>
                            </strong>
                            <span class="badge bg-secondary ms-1">
                                v<?= h($template['ObjectTemplate']['version']) ?>
                            </span>
                            <br>
                            <small class="text-muted">
                                <?= h($template['ObjectTemplate']['description']) ?>
                            </small>
                        <?php endif; ?>
                    </div>

                    <div class="d-flex justify-content-end mt-3">
                        <button type="button"
                                id="objNextBtn"
                                class="btn btn-object"
                                <?= !$hasTemplate ? 'disabled' : '' ?>>
                            <?= __('Next') ?>
                            <i class="fas fa-chevron-down ms-1"></i>
                        </button>
                    </div>

                </div>
            </div>
        </div>

        <!-- ===== STEP 2 : OBJECT FORM ===== -->
        <div class="accordion-item border mb-2 rounded shadow-sm">
            <h2 class="accordion-header" id="objHeading2">
                <button class="accordion-button <?= !$hasTemplate ? 'collapsed' : '' ?> rounded"
                        type="button"
                        aria-expanded="<?= $hasTemplate ? 'true' : 'false' ?>"
                        aria-controls="objCollapse2"
                        style="cursor:default; pointer-events:none;">
                    <span class="badge bg-object me-2">2</span>
                    <?= __('Object') ?>
                </button>
            </h2>
            <div id="objCollapse2"
                 class="accordion-collapse collapse <?= $hasTemplate ? 'show' : '' ?>"
                 aria-labelledby="objHeading2"
                 data-bs-parent="#objectAccordion">
                <div class="accordion-body">

                    <?php if (!$hasTemplate): ?>

                        <!-- Placeholder when no template selected -->
                        <div class="text-center text-muted py-5">
                            <i class="fas fa-arrow-up fa-2x mb-3 d-block opacity-50"></i>
                            <?= __('Please select a template in Step 1 first.') ?>
                        </div>

                    <?php else: ?>

                        <!-- Template meta info -->
                        <div class="row g-3 mb-4 pb-3"
                             style="border-bottom:1px solid var(--bs-border-color);">
                            <div class="col-md-6">
                                <div class="text-object fw-bold text-uppercase mb-1"
                                     style="font-size:.65rem; letter-spacing:.1em;">
                                    <?= __('Template') ?>
                                </div>
                                <div class="d-flex align-items-center gap-2 flex-wrap">
                                    <strong>
                                        <?= h(Inflector::humanize($template['ObjectTemplate']['name'])) ?>
                                    </strong>
                                    <span class="badge bg-secondary">
                                        v<?= h($template['ObjectTemplate']['version']) ?>
                                    </span>
                                    <span class="badge bg-object">
                                        <?= h($template['ObjectTemplate']['meta-category']) ?>
                                    </span>
                                </div>
                                <div class="text-muted small mt-1">
                                    <?= h($template['ObjectTemplate']['description']) ?>
                                </div>
                            </div>

                            <?php if (
                                !empty($template['ObjectTemplate']['requirements']['required']) ||
                                !empty($template['ObjectTemplate']['requirements']['requiredOneOf'])
                            ): ?>
                                <div class="col-md-6">
                                    <div class="text-object fw-bold text-uppercase mb-1"
                                         style="font-size:.65rem; letter-spacing:.1em;">
                                        <?= __('Requirements') ?>
                                    </div>
                                    <?php if (!empty($template['ObjectTemplate']['requirements']['required'])): ?>
                                        <div class="small">
                                            <strong><?= __('Required') ?>:</strong>
                                            <?= h(implode(', ', $template['ObjectTemplate']['requirements']['required'])) ?>
                                        </div>
                                    <?php endif; ?>
                                    <?php if (!empty($template['ObjectTemplate']['requirements']['requiredOneOf'])): ?>
                                        <div class="small">
                                            <strong><?= __('Required one of') ?>:</strong>
                                            <?= h(implode(', ', $template['ObjectTemplate']['requirements']['requiredOneOf'])) ?>
                                        </div>
                                    <?php endif; ?>
                                </div>
                            <?php endif; ?>
                        </div>

                        <!-- Distribution cards -->
                        <?php
                        $distIconMap = $this->DistributionLevel->all();
                        $initDist = (int)$distributionData['initial'];
                        ?>
                        <div class="mb-3">
                            <div class="text-object fw-bold text-uppercase mb-2"
                                 style="font-size:.65rem; letter-spacing:.1em;">
                                <?= __('Distribution') ?>
                            </div>
                            <?= $this->Form->select(
                                'Object.distribution',
                                $distributionData['levels'],
                                [
                                    'id'      => 'ObjectDistribution',
                                    'class'   => 'Object_distribution_select',
                                    'default' => $distributionData['initial'],
                                    'style'   => 'display:none;',
                                ]
                            ) ?>
                            <div class="row g-2" id="distCardRow">
                                <?php foreach ($distributionData['levels'] as $level => $label):
                                    $level = (int)$level;
                                    $ic = $distIconMap[$level]
                                        ?? ['bg' => '#f1f1f1', 'color' => '#333',
                                            'icon' => 'fas fa-question'];
                                    $sel = ($level === $initDist);
                                    $bdr = $sel
                                        ? 'border-color:var(--bs-object) !important;background:rgba(82,73,72,.08);'
                                        : 'border-color:#d8dde3;';
                                ?>
                                <div class="col dist-card-col"
                                     style="cursor:pointer;"
                                     data-dist-value="<?= $level ?>">
                                    <div class="border rounded p-2 d-flex flex-column align-items-center gap-1 h-100 text-center"
                                         style="transition:border-color .15s,background .15s;
                                                <?= $bdr ?>">
                                        <span class="d-inline-flex align-items-center justify-content-center rounded-circle mb-1"
                                              style="width:1.8rem;height:1.8rem;
                                                     background:<?= h($ic['bg']) ?>;
                                                     border:1px solid <?= h($ic['color']) ?>30;">
                                            <i class="<?= h($ic['icon']) ?>"
                                               style="color:<?= h($ic['color']) ?>;font-size:.7rem;"></i>
                                        </span>
                                        <span class="fw-bold lh-sm"
                                              style="font-size:.68rem;color:var(--bs-body-color);">
                                            <?= h($label) ?>
                                        </span>
                                    </div>
                                </div>
                                <?php endforeach; ?>
                            </div>
                        </div>

                        <!-- Sharing Group (conditional) -->
                        <div class="mb-3"
                             id="objectSGWrapper"
                             style="<?= ($initDist == 4) ? '' : 'display:none;' ?>">
                            <div class="text-object fw-bold text-uppercase mb-2"
                                 style="font-size:.65rem; letter-spacing:.1em;">
                                <?= __('Sharing Group') ?>
                            </div>
                            <?= $this->Form->select(
                                'Object.sharing_group_id',
                                $distributionData['sgs'],
                                [
                                    'id'    => 'ObjectSharingGroup',
                                    'class' => 'form-select',
                                ]
                            ) ?>
                        </div>

                        <!-- First Seen / Last Seen -->
                        <div class="row g-3 mb-3">
                            <div class="col-md-6">
                                <div class="text-object fw-bold text-uppercase mb-2"
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
                                           id="obj-first-seen-picker"
                                           class="form-control border-start-0"
                                           style="border-color:#d8dde3;">
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="text-object fw-bold text-uppercase mb-2"
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
                                           id="obj-last-seen-picker"
                                           class="form-control border-start-0"
                                           style="border-color:#d8dde3;">
                                </div>
                            </div>
                        </div>
                        <?= $this->Form->hidden('first_seen', [
                            'id' => 'ObjectFirstSeen', 'value' => '',
                        ]) ?>
                        <?= $this->Form->hidden('last_seen', [
                            'id' => 'ObjectLastSeen', 'value' => '',
                        ]) ?>

                        <!-- Comment -->
                        <div class="mb-4">
                            <div class="text-object fw-bold text-uppercase mb-2"
                                 style="font-size:.65rem; letter-spacing:.1em;">
                                <?= __('Comment') ?>
                            </div>
                            <?= $this->Form->textarea(
                                'Object.comment',
                                [
                                    'class'      => 'form-control',
                                    'rows'       => 2,
                                    'required'   => false,
                                    'allowEmpty' => true,
                                    'placeholder' => __('Optional comment…'),
                                    'label'      => false,
                                    'div'        => false,
                                ]
                            ) ?>
                        </div>

                        <!-- Template warnings -->
                        <?php if (!empty($template['warnings'])): ?>
                            <div class="alert alert-warning mb-4">
                                <strong>
                                    <?= __('Warning, issues found with the template') ?>:
                                </strong>
                                <?php foreach ($template['warnings'] as $warning): ?>
                                    <div><?= h($warning) ?></div>
                                <?php endforeach; ?>
                            </div>
                        <?php endif; ?>

                        <!-- Attributes table -->
                        <div class="text-object fw-bold text-uppercase mb-2"
                             style="font-size:.65rem; letter-spacing:.1em;">
                            <?= __('Attributes') ?>
                        </div>

                        <div id="editTable" class="mb-4">
                            <?php
                            $row_list = [];
                            foreach ($template['ObjectTemplateElement'] as $k => $element):
                                $row_list[] = $k;
                                echo $this->element(
                                    'Objects/object_add_attributes',
                                    [
                                        'element'     => $element,
                                        'k'           => $k,
                                        'action'      => $action,
                                        'enabledRows' => $enabledRows,
                                    ]
                                );
                                if ($element['multiple']):
                                    $lastOfType = true;
                                    $lookAhead  = array_slice(
                                        $template['ObjectTemplateElement'],
                                        $k,
                                        count($template['ObjectTemplateElement']),
                                        true
                                    );
                                    if (count($lookAhead) > 1) {
                                        foreach ($lookAhead as $k2 => $temp) {
                                            if ($k2 === $k) continue;
                                            if ($temp['object_relation'] === $element['object_relation']) {
                                                $lastOfType = false;
                                                break;
                                            }
                                        }
                                    }
                                    if ($lastOfType):
                            ?>
                                <div id="row_<?= h($element['object_relation']) ?>_expand"
                                     class="add_object_attribute_row text-center py-2 mb-2 rounded"
                                     style="cursor:pointer;
                                            border:1px dashed #d8dde3;
                                            background:rgba(82,73,72,.02);
                                            transition:background .15s;"
                                     title="<?= __('Add another %s attribute', h($element['object_relation'])) ?>"
                                     data-template-id="<?= intval($template['ObjectTemplate']['id']) ?>"
                                     data-target-row="<?= intval($k) ?>"
                                     data-object-relation="<?= h($element['object_relation']) ?>">
                                    <i class="fas fa-plus text-object"
                                       style="font-size:.7rem;"></i>
                                    <span class="ms-1 text-object fw-bold text-uppercase"
                                          style="font-size:.65rem; letter-spacing:.06em;">
                                        <?= __('Add another %s', h(Inflector::humanize($element['object_relation']))) ?>
                                    </span>
                                </div>
                            <?php
                                    endif;
                                endif;
                            endforeach;
                            ?>
                        </div>

                        <!-- Hidden counter for "add another row" -->
                        <div id="last-row" class="d-none" data-last-row="<?= h($k) ?>"></div>

                        <!-- Actions -->
                        <div class="d-flex justify-content-between align-items-center mt-3">
                            <button type="button"
                                    class="btn btn-outline-secondary"
                                    id="objPrevBtn">
                                <i class="fas fa-chevron-up me-1"></i>
                                <?= __('Previous') ?>
                            </button>
                            <div class="d-flex align-items-center gap-3">
                                <p class="text-danger fw-bold d-none mb-0" id="warning-message">
                                    <?= __('Warning: You are about to share data that is of a classified nature. Make sure that you are authorised to share this.') ?>
                                </p>
                                <button type="button"
                                        class="btn btn-primary"
                                        id="objReviewBtn">
                                    <i class="fas fa-eye me-1"></i>
                                    <?= __('Review') ?>
                                    <i class="fas fa-chevron-down ms-1"></i>
                                </button>
                            </div>
                        </div>

                    <?php endif; ?>

                </div>
            </div>
        </div>

        <!-- ===== STEP 3 : REVIEW ===== -->
        <div class="accordion-item border mb-2 rounded shadow-sm">
            <h2 class="accordion-header" id="objHeading3">
                <button class="accordion-button collapsed rounded"
                        type="button"
                        aria-expanded="false"
                        aria-controls="objCollapse3"
                        style="cursor:default; pointer-events:none;">
                    <span class="badge bg-object me-2">3</span>
                    <?= __('Review') ?>
                </button>
            </h2>
            <div id="objCollapse3"
                 class="accordion-collapse collapse"
                 aria-labelledby="objHeading3"
                 data-bs-parent="#objectAccordion">
                <div class="accordion-body p-3">

                    <!-- Preview area — populated by JS on "Review" click -->
                    <div id="objReviewBody" class="mb-3">
                        <div class="text-center text-muted py-4 fst-italic">
                            <i class="fas fa-eye d-block mb-2 opacity-25"
                               style="font-size:2rem;"></i>
                            <?= __('Click "Review" in Step 2 to preview the object before submitting.') ?>
                        </div>
                    </div>

                    <!-- Actions -->
                    <div class="d-flex justify-content-between align-items-center mt-2">
                        <button type="button"
                                class="btn btn-outline-secondary"
                                id="objPrevBtn3">
                            <i class="fas fa-chevron-up me-1"></i>
                            <?= __('Previous') ?>
                        </button>
                        <div class="d-flex align-items-center gap-3">
                            <p class="text-danger fw-bold d-none mb-0"
                               id="warning-message">
                                <?= __('Warning: You are about to share data that is of a classified nature. Make sure that you are authorised to share this.') ?>
                            </p>
                            <button type="submit"
                                    class="btn btn-success"
                                    id="submitButton">
                                <i class="fas fa-check me-1"></i>
                                <?= __('Submit') ?>
                            </button>
                        </div>
                    </div>

                </div>
            </div>
        </div>

    </div><!-- /accordion -->
</div><!-- /container-fluid -->

<?php echo $this->Form->end(); ?>

<script>
(function () {
    'use strict';

    var eventId = <?= json_encode($eventId) ?>;

    /* ── Vanilla-JS shim used by get_row.ctp ────────────────── */
    window.overmindEnableObjectRow = function (k) {
        var saveEl  = document.getElementById('Attribute' + k + 'Save');
        var valEl   = document.getElementById('Attribute' + k + 'Value');
        var selEl   = document.getElementById('Attribute' + k + 'ValueSelect');
        var fileEl  = document.getElementById('Attribute' + k + 'Attachment');
        var card    = saveEl ? saveEl.closest('.attribute_row') : null;

        function syncCardOpacity() {
            if (card) card.style.opacity = (saveEl && saveEl.checked) ? '1' : '.5';
        }

        function syncSave() {
            if (!saveEl) return;
            var hasVal = selEl  ? selEl.value  !== '' :
                         fileEl ? fileEl.value !== '' :
                         valEl  ? valEl.value.trim() !== '' : false;
            saveEl.checked  = hasVal;
            saveEl.disabled = !hasVal;
            syncCardOpacity();
        }

        if (saveEl) saveEl.addEventListener('change', syncCardOpacity);

        syncSave();
        if (valEl)  valEl.addEventListener('input',  syncSave);
        if (selEl)  selEl.addEventListener('change', syncSave);
        if (fileEl) fileEl.addEventListener('change', syncSave);

        /* Value-select → manual-entry textarea sync */
        if (selEl) {
            var wrap    = selEl.closest('.value_select_with_manual_entry');
            var textVal = wrap ? wrap.querySelector('textarea') : null;
            if (textVal) {
                function syncTextarea() {
                    var manual = selEl.value === 'Enter value manually';
                    textVal.style.display = manual ? '' : 'none';
                }
                selEl.addEventListener('change', syncTextarea);
                syncTextarea();
            }
        }
    };

    /* ── IDS / Correlate toggle card visual sync ─────────── */
    document.addEventListener('change', function (e) {
        if (e.target.type !== 'checkbox') return;

        var idsCard = e.target.closest('[id^="card-ids-"]');
        if (idsCard) {
            var idsIcon = idsCard.querySelector('.fa-shield-halved');
            var on      = e.target.checked;
            idsCard.style.borderColor = on ? '#ffc107' : '#dee2e6';
            idsCard.style.background  = on ? 'rgba(255,193,7,.08)' : 'transparent';
            if (idsIcon) idsIcon.style.color = on ? '#ffc107' : '#adb5bd';
            return;
        }

        var corrCard = e.target.closest('[id^="card-corr-"]');
        if (corrCard) {
            var corrIcon = corrCard.querySelector('i');
            var corrOn   = !e.target.checked; /* disable_correlation=false → ON */
            corrCard.style.borderColor = corrOn ? '#198754' : '#dee2e6';
            corrCard.style.background  = corrOn ? 'rgba(25,135,84,.08)' : 'transparent';
            if (corrIcon) {
                corrIcon.style.color = corrOn ? '#198754' : '#adb5bd';
                if (corrOn) {
                    corrIcon.classList.remove('fa-link-slash');
                    corrIcon.classList.add('fa-link');
                } else {
                    corrIcon.classList.remove('fa-link');
                    corrIcon.classList.add('fa-link-slash');
                }
            }
            return;
        }
    });

    <?php if ($hasTemplate): ?>
    /* ── Row enable/disable for initial rows ─────────────────── */
    var rows = <?= json_encode($row_list) ?>;
    rows.forEach(function (k) { window.overmindEnableObjectRow(k); });

    /* ── Distribution cards ──────────────────────────────────── */
    var objDistSel = document.getElementById('ObjectDistribution');
    var sgWrapper  = document.getElementById('objectSGWrapper');

    document.querySelectorAll('.dist-card-col').forEach(function (card) {
        card.addEventListener('click', function () {
            var val = card.dataset.distValue;
            document.querySelectorAll('.dist-card-col > div').forEach(function (d) {
                d.style.borderColor = '#d8dde3';
                d.style.background  = '';
            });
            var inner = card.querySelector('div');
            if (inner) {
                inner.style.borderColor = 'var(--bs-object)';
                inner.style.background  = 'rgba(82,73,72,.08)';
            }
            if (objDistSel) objDistSel.value = val;
            if (sgWrapper) sgWrapper.style.display = (val == 4) ? '' : 'none';
        });
    });

    /* ── First / Last Seen picker → hidden input sync ─────────── */
    var firstPicker = document.getElementById('obj-first-seen-picker');
    var lastPicker  = document.getElementById('obj-last-seen-picker');
    var firstHidden = document.getElementById('ObjectFirstSeen');
    var lastHidden  = document.getElementById('ObjectLastSeen');
    if (firstPicker && firstHidden) {
        firstPicker.addEventListener('change', function () {
            firstHidden.value = firstPicker.value.replace('T', ' ');
        });
    }
    if (lastPicker && lastHidden) {
        lastPicker.addEventListener('change', function () {
            lastHidden.value = lastPicker.value.replace('T', ' ');
        });
    }

    /* ── Per-attribute distribution → SG select ─────────────── */
    document.querySelectorAll('.Attribute_distribution_select').forEach(function (sel) {
        var sgSel = sel.parentNode
            ? sel.parentNode.querySelector('.Attribute_sharing_group_id_select')
            : null;
        if (sgSel) {
            sel.addEventListener('change', function () {
                sgSel.style.display = sel.value == 4 ? '' : 'none';
            });
        }
    });

    /* ── "Add another attribute" row expand ─────────────────── */
    document.addEventListener('click', function (e) {
        var btn = e.target.closest('.add_object_attribute_row');
        if (!btn) return;
        var templateId     = btn.dataset.templateId;
        var objectRelation = btn.dataset.objectRelation;
        var lastRow        = document.getElementById('last-row');
        var k = lastRow ? (parseInt(lastRow.dataset.lastRow, 10) + 1) : 0;
        if (lastRow) lastRow.dataset.lastRow = k;

        fetch(baseurl + '/objects/get_row/' + templateId + '/' + objectRelation + '/' + k, {
            headers: { 'X-Requested-With': 'XMLHttpRequest' }
        })
        .then(function (r) { return r.text(); })
        .then(function (html) {
            var expandRow = document.getElementById('row_' + objectRelation + '_expand');
            if (!expandRow) return;
            /* Cards are divs — parse as plain HTML, no table wrapper needed */
            var doc = new DOMParser().parseFromString(html, 'text/html');
            Array.from(doc.body.childNodes).forEach(function (node) {
                if (node.nodeType !== 1) return;
                if (node.tagName === 'DIV') {
                    expandRow.parentNode.insertBefore(
                        node.cloneNode(true), expandRow
                    );
                } else if (node.tagName === 'SCRIPT') {
                    var s = document.createElement('script');
                    s.textContent = node.textContent;
                    document.head.appendChild(s);
                    document.head.removeChild(s);
                }
            });
        });
    });

    /* ── Previous button (step 2 → step 1) ──────────────────── */
    var prevBtn = document.getElementById('objPrevBtn');
    if (prevBtn) {
        prevBtn.addEventListener('click', function () {
            var el = document.getElementById('objCollapse1');
            if (el) bootstrap.Collapse.getOrCreateInstance(el).show();
        });
    }

    /* ── Review ──────────────────────────────────────────────── */

    var distLevels           = <?= json_encode($distributionData['levels']) ?>;
    var templateNameDisp     = <?= json_encode(Inflector::humanize($template['ObjectTemplate']['name'])) ?>;
    var templateMetaDisp     = <?= json_encode($template['ObjectTemplate']['meta-category']) ?>;
    var templateVersionDisp  = <?= json_encode($template['ObjectTemplate']['version'] ?? '') ?>;

    function buildReview() {
        /* ── Collect object-level data ── */
        var distEl    = document.getElementById('ObjectDistribution');
        var dist      = distEl ? parseInt(distEl.value, 10) : 0;
        var cmtEl     = document.getElementById('ObjectComment');
        var comment   = cmtEl  ? cmtEl.value.trim()  : '';
        var fsHidden  = document.getElementById('ObjectFirstSeen');
        var lsHidden  = document.getElementById('ObjectLastSeen');
        var firstSeen = fsHidden ? fsHidden.value : '';
        var lastSeen  = lsHidden ? lsHidden.value  : '';

        /* ── Collect saved attribute rows ── */
        var attrs = [];
        document.querySelectorAll('.attribute_row').forEach(function (card) {
            var k      = card.id.replace('row_', '');
            var saveEl = document.getElementById('Attribute' + k + 'Save');
            if (!saveEl || !saveEl.checked) return;

            var valEl = document.getElementById('Attribute' + k + 'Value');
            var selEl = document.getElementById('Attribute' + k + 'ValueSelect');
            var value = '';
            if (selEl && selEl.value && selEl.value !== 'Enter value manually') {
                value = selEl.value;
            } else if (valEl) {
                value = valEl.value.trim();
            }

            var typeEl   = document.getElementById('Attribute' + k + 'Type');
            var catEl    = document.getElementById('Attribute' + k + 'Category');
            var idsEl    = document.getElementById('Attribute' + k + 'ToIds');
            var corrEl   = document.getElementById('Attribute' + k + 'DisableCorrelation');
            var distAtEl = document.getElementById('Attribute' + k + 'Distribution');
            var relEl    = document.getElementById('Attribute' + k + 'ObjectRelation');
            var atCmtEl  = document.getElementById('Attribute' + k + 'Comment');

            attrs.push({
                relation:  relEl    ? relEl.value : '',
                value:     value,
                type:      typeEl   ? typeEl.value : '',
                category:  catEl
                    ? (catEl.options[catEl.selectedIndex]
                        ? catEl.options[catEl.selectedIndex].text
                        : catEl.value)
                    : '',
                to_ids:    idsEl    ? idsEl.checked   : false,
                correlate: corrEl   ? !corrEl.checked : true,
                dist:      distAtEl ? parseInt(distAtEl.value, 10) : 0,
                comment:   atCmtEl  ? atCmtEl.value.trim() : '',
            });
        });

        /* ── Distribution warning ── */
        var warnEl = document.getElementById('warning-message');
        if (warnEl) warnEl.classList.toggle('d-none', dist < 3);

        /* ── Render: matches index.ctp accordion-item structure ── */
        var html = '<div class="accordion">'
            + '<div class="accordion-item shadow-sm rounded border">';

        /* Object header: non-interactive accordion-button (expanded state) */
        html += '<h2 class="accordion-header">'
            + '<div class="accordion-button py-2 px-3"'
            + ' style="pointer-events:none; cursor:default;">'
            + '<span class="d-flex align-items-center flex-wrap gap-2 w-100 me-2">';
        html += distBadgeHtml(dist, false);
        html += '<span class="fw-semibold">'
            + '<span class="misp-icon misp-icon-object misp-hexagone me-1 text-secondary"></span>'
            + escapeHtml(templateNameDisp) + '</span>';
        html += '<span class="badge rounded-pill text-bg-light border text-secondary fw-normal">'
            + escapeHtml(templateMetaDisp) + '</span>';
        if (comment) {
            html += '<span class="text-muted fst-italic small text-truncate"'
                + ' style="max-width:400px;">'
                + '<i class="fas fa-comment fa-xs me-1"></i>'
                + escapeHtml(comment) + '</span>';
        }
        html += '<span class="badge rounded-pill bg-secondary-subtle text-secondary ms-auto">'
            + attrs.length + (attrs.length !== 1 ? ' attributes' : ' attribute')
            + '</span>';
        var today = new Date().toISOString().slice(0, 10);
        html += '<span class="text-muted small text-nowrap">'
            + '<i class="fas fa-clock fa-xs me-1"></i>' + today + '</span>';
        html += '</span>'   /* w-100 me-2 */
            + '</div>'      /* accordion-button */
            + '</h2>';      /* accordion-header */

        /* Body */
        html += '<div class="accordion-collapse collapse show">'
            + '<div class="accordion-body p-0">';

        /* Meta row: first_seen / last_seen / template version */
        html += '<div class="px-3 py-2 bg-light border-bottom'
            + ' d-flex flex-wrap align-items-center gap-3 small text-muted">';
        if (firstSeen) {
            html += '<span><i class="fas fa-calendar-plus me-1"></i>'
                + escapeHtml(firstSeen) + '</span>';
        }
        if (lastSeen) {
            html += '<span><i class="fas fa-calendar-check me-1"></i>'
                + escapeHtml(lastSeen) + '</span>';
        }
        html += '<span>'
            + '<span class="misp-icon misp-icon-tag misp-hexagone me-1"></span>'
            + 'Template v' + escapeHtml(String(templateVersionDisp))
            + '</span>';
        html += '</div>';

        /* Attribute table — columns match index.ctp:
           spacer | Value | Type (=Category+Relation) | Category (=Type) | IDS | Correlate */
        if (attrs.length > 0) {
            html += '<div class="table-responsive">'
                + '<table class="table table-sm table-hover align-middle mb-0">'
                + '<thead class="table-light"><tr>'
                + '<th class="ps-3" style="width:1%"></th>'
                + '<th style="width:35%">Value</th>'
                + '<th style="width:15%">Type</th>'
                + '<th style="width:15%">Category</th>'
                + '<th class="text-center" style="width:5%">IDS</th>'
                + '<th class="text-center pe-3" style="width:5%">Correlate</th>'
                + '</tr></thead><tbody>';

            attrs.forEach(function (a) {
                /* Value: dist badge + value text + optional comment card
                   (mirrors attribute_value.ctp) */
                var valueHtml = '<div class="d-flex flex-column gap-1">'
                    + '<div class="d-flex align-items-baseline gap-2 mb-0">'
                    + distBadgeHtml(a.dist, false)
                    + '<p class="mb-0">' + escapeHtml(a.value || '—') + '</p>'
                    + '</div>';
                if (a.comment) {
                    valueHtml += '<div class="card card-link-item bg-light">'
                        + '<div class="card-body p-1">'
                        + '<i class="fa fa-comment"></i> '
                        + '<span>' + escapeHtml(a.comment) + '</span>'
                        + '</div></div>';
                }
                valueHtml += '</div>';

                /* "Type" col: category.ctp (italic + chevron) + type.ctp (dark pill) */
                var typeColHtml = '<div class="d-flex align-items-center gap-1">'
                    + '<div class="d-flex align-items-center text-nowrap">'
                    + '<p class="fst-italic mb-0">' + escapeHtml(a.category) + '</p>'
                    + (a.relation
                        ? '<i class="fa-solid fa-chevron-right ms-1"></i>'
                        : '')
                    + '</div>';
                if (a.relation) {
                    typeColHtml += '<div class="d-flex align-items-center">'
                        + '<p class="border border-dark rounded p-1 mb-0 bg-dark text-white"'
                        + ' style="font-size:inherit;">'
                        + escapeHtml(a.relation) + '</p>'
                        + '</div>';
                }
                typeColHtml += '</div>';

                /* "Category" col: type.ctp (border border-dark rounded p-1) */
                var catColHtml = '<div class="d-flex align-items-center">'
                    + '<p class="border border-dark rounded p-1 mb-0">'
                    + escapeHtml(a.type) + '</p>'
                    + '</div>';

                /* IDS: ids.ctp table mode */
                var idsHtml = a.to_ids
                    ? '<i class="fas fa-shield-halved text-warning"'
                    +   ' style="font-size:1.2em;"></i>'
                    : '<i class="fas fa-shield-halved text-secondary"'
                    +   ' style="font-size:1.2em;"></i>';

                /* Correlate: correlate.ctp table mode */
                var corrHtml = a.correlate
                    ? '<i class="fas fa-link text-success"'
                    +   ' style="font-size:1.2em;"></i>'
                    : '<i class="fas fa-link-slash text-secondary"'
                    +   ' style="font-size:1.2em;"></i>';

                html += '<tr>'
                    + '<td class="ps-3"></td>'
                    + '<td class="text-break">' + valueHtml + '</td>'
                    + '<td>' + typeColHtml + '</td>'
                    + '<td>' + catColHtml + '</td>'
                    + '<td class="text-center">' + idsHtml + '</td>'
                    + '<td class="text-center pe-3">' + corrHtml + '</td>'
                    + '</tr>';
            });

            html += '</tbody></table></div>';
        } else {
            html += '<p class="text-muted small fst-italic px-3 py-2 mb-0">'
                + '<i class="fas fa-info-circle me-1"></i>'
                + 'No attributes will be saved.</p>';
        }

        html += '</div>'    /* accordion-body */
            + '</div>'      /* accordion-collapse */
            + '</div>'      /* accordion-item */
            + '</div>';     /* accordion */

        var container = document.getElementById('objReviewBody');
        if (container) container.innerHTML = html;
    }

    /* Review button → build preview + open step 3 */
    var reviewBtn = document.getElementById('objReviewBtn');
    if (reviewBtn) {
        reviewBtn.addEventListener('click', function () {
            buildReview();
            var el = document.getElementById('objCollapse3');
            if (el) bootstrap.Collapse.getOrCreateInstance(el).show();
        });
    }

    /* Previous button (step 3 → step 2) */
    var prevBtn3 = document.getElementById('objPrevBtn3');
    if (prevBtn3) {
        prevBtn3.addEventListener('click', function () {
            var el = document.getElementById('objCollapse2');
            if (el) bootstrap.Collapse.getOrCreateInstance(el).show();
        });
    }
    <?php endif; ?>

    /* ── Step 1: template picker ─────────────────────────────── */
    var allTemplates = <?= json_encode(array_map(function ($t) {
        return [
            'id'      => (string)$t['ObjectTemplate']['id'],
            'name'    => Inflector::humanize($t['ObjectTemplate']['name']),
            'meta'    => $t['ObjectTemplate']['meta-category'],
            'desc'    => $t['ObjectTemplate']['description'],
            'version' => $t['ObjectTemplate']['version'],
        ];
    }, $templateList)) ?>;

    var tsInstance   = null;
    var nextBtn      = document.getElementById('objNextBtn');
    var descPreview  = document.getElementById('templateDescPreview');
    var nativeSel    = document.getElementById('objectTemplateSelect');
    var metaBtns     = document.querySelectorAll('.meta-cat-btn');
    var activeMeta   = '';

    function onTemplateChange(value) {
        if (value) {
            if (nextBtn) nextBtn.removeAttribute('disabled');
            var opt = allTemplates.find(function (t) { return t.id === value; });
            if (opt && descPreview) {
                descPreview.classList.remove('d-none');
                descPreview.innerHTML =
                    '<strong>' + escapeHtml(opt.name) + '</strong>' +
                    ' <span class="badge bg-secondary ms-1">v' + escapeHtml(opt.version) + '</span>' +
                    '<br><small class="text-muted">' + escapeHtml(opt.desc) + '</small>';
            }
        } else {
            if (nextBtn) nextBtn.setAttribute('disabled', '');
            if (descPreview) descPreview.classList.add('d-none');
        }
    }

    /* TomSelect init */
    if (typeof TomSelect !== 'undefined' && nativeSel) {
        tsInstance = new TomSelect(nativeSel, {
            allowEmptyOption: true,
            create:           false,
            placeholder:      <?= json_encode(__('-- Select a template --')) ?>,
            onChange:         onTemplateChange,
        });
        /* Restore pre-selected template when page reloads with templateId */
        <?php if ($hasTemplate): ?>
        tsInstance.setValue(<?= json_encode($templateId) ?>, true);
        <?php endif; ?>
    } else if (nativeSel) {
        nativeSel.addEventListener('change', function () {
            onTemplateChange(nativeSel.value);
        });
    }

    /* Meta-category badge filter */
    function filterByMeta(meta) {
        activeMeta = meta;
        if (tsInstance) {
            tsInstance.clearOptions();
            /* Re-add the empty placeholder after clearOptions */
            tsInstance.addOption({ value: '', text: '' });
            var filtered = meta
                ? allTemplates.filter(function (t) { return t.meta === meta; })
                : allTemplates;
            filtered.forEach(function (t) {
                tsInstance.addOption({
                    value: t.id,
                    text:  t.name + ' (' + t.meta + ')',
                    id:    t.id, name: t.name, meta: t.meta,
                    desc:  t.desc, version: t.version,
                });
            });
            tsInstance.clear();
            tsInstance.refreshOptions(false);
            if (nextBtn) nextBtn.setAttribute('disabled', '');
            if (descPreview) descPreview.classList.add('d-none');
        } else if (nativeSel) {
            Array.from(nativeSel.options).forEach(function (opt) {
                if (!opt.value) return;
                opt.hidden = meta !== '' && opt.dataset.meta !== meta;
            });
            nativeSel.value = '';
            if (nextBtn) nextBtn.setAttribute('disabled', '');
            if (descPreview) descPreview.classList.add('d-none');
        }
    }

    metaBtns.forEach(function (btn) {
        btn.addEventListener('click', function () {
            metaBtns.forEach(function (b) { b.classList.remove('active'); });
            btn.classList.add('active');
            filterByMeta(btn.dataset.meta);
        });
    });

    /* Next button → reload modal with the selected template */
    if (nextBtn) {
        nextBtn.addEventListener('click', function () {
            var val = tsInstance ? tsInstance.getValue() : (nativeSel ? nativeSel.value : '');
            if (val && typeof openModal === 'function') {
                openModal(baseurl + '/objects/add/' + eventId + '/' + val);
            } else if (val) {
                window.location.href = baseurl + '/objects/add/' + eventId + '/' + val;
            }
        });
    }

}());
</script>
