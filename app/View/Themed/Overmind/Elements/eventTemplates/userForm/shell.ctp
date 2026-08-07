<?php
    $tpl = $data['EventTemplate'] ?? [];
    $structure = isset($definition['structure']) && is_array($definition['structure'])
        ? $definition['structure']
        : [];
    $templateDescription = isset($tpl['description']) ? (string)$tpl['description'] : '';
    $templateName = isset($tpl['name']) ? (string)$tpl['name'] : '';
    $specs = isset($objectRelationSpecs) ? $objectRelationSpecs : [];
    $isPreview = !empty($isPreview);
    $templateId = (int)($tpl['id'] ?? 0);

    // object_reference elements never render into the user form — they
    // materialise at instantiation time based on the filled object_fields.
    $renderableTypes = [
        'section', 'text_block', 'attribute_field', 'object_field',
        'tag_field', 'galaxy_field', 'file_field', 'event_report',
    ];


    $groups = [];
    $current = ['section' => null, 'children' => []];
    foreach ($structure as $el) {
        if (!is_array($el) || empty($el['type'])) { continue; }
        if ($el['type'] === 'section') {
            if (!empty($current['children']) || $current['section'] !== null) {
                $groups[] = $current;
            }
            $current = ['section' => $el, 'children' => []];
            continue;
        }
        if (!in_array($el['type'], $renderableTypes, true)) { continue; }
        $current['children'][] = $el;
    }
    if (!empty($current['children']) || $current['section'] !== null) {
        $groups[] = $current;
    }
    $stepCount = count($groups);

    $isModal = !empty($ajax);
    $pageTitle = __('Create Event from Template');
    if (!$isModal) {
        $this->set('headerTitle', $templateName !== '' ? $templateName : $pageTitle);
        $this->set('headerDescription', __('Fill the template step by step — MISP builds the event, its attributes and its objects from your answers.'));
        $this->set('headerCountText', '');
    }
?>

<?php if ($isModal): ?>
<!-- ── MODAL HEADER ─────────────────────────────────────────── -->
<div class="px-4 pt-3 pb-3 d-flex align-items-center justify-content-between"
     style="background:rgba(24,146,177,.06);
            border-bottom:2px solid var(--event, var(--primary));">
    <div>
        <div class="text-uppercase fw-semibold mb-1 text-event"
             style="font-size:.58rem; letter-spacing:.12em; opacity:.85;">
            <?= __('Event Templates') ?>
        </div>
        <h4 class="mb-0 fw-bold d-flex align-items-center gap-2">
            <i class="fas fa-<?= $isPreview ? 'eye' : 'bolt' ?> text-event"
               style="font-size:1.25rem;"></i>
            <?= h($templateName !== '' ? $templateName : $pageTitle) ?>
        </h4>
        <p class="text-muted mb-0" style="font-size:.75rem;">
            <?= $isPreview
                ? __('Preview — walk through the steps a reporter sees. Nothing is created.')
                : __('Answer each step — MISP builds the event, its attributes and its objects from your answers.') ?>
        </p>
    </div>
    <span class="fas fa-wand-magic-sparkles text-event"
          style="font-size:2rem; opacity:.5;"></span>
</div>
<?php endif; ?>

<div class="event-template-user-form <?= $isModal ? 'p-4' : 'container-fluid px-4 py-3' ?>">

    <?php if ($isPreview): ?>
        <div class="alert alert-warning et-preview-banner d-flex align-items-start gap-2" role="alert">
            <i class="fas fa-eye mt-1"></i>
            <div>
                <strong><?= __('Preview mode') ?>.</strong>
                <?= __('This is what a template user will see.') ?>
            </div>
        </div>
    <?php endif; ?>

    <?php if ($templateDescription !== ''): ?>
        <div class="mb-4">
            <div class="text-primary fw-bold text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('About this template') ?>
            </div>
            <div class="et-template-description text-muted" style="font-size:.85rem;">
                <?= $this->EventTemplateMarkdown->render($templateDescription) ?>
            </div>
        </div>
    <?php endif; ?>

    <div class="et-errors-panel alert alert-danger"
         id="et-user-form-errors"
         style="display:none;"></div>

    <form id="et-user-form"
          data-et-template-id="<?= (int)$templateId ?>"
          data-et-instantiate-url="<?= h($baseurl . '/event_templates/instantiate/' . $templateId) ?>">

        <?php if ($stepCount === 0): ?>
            <div class="text-muted fst-italic">
                <?= __('This template has no fields yet — nothing to fill in.') ?>
            </div>
        <?php endif; ?>

        <!-- ── STEPS ──────────────────────────────────────────── -->
        <div class="accordion" id="etStepAccordion">
            <?php foreach ($groups as $index => $group): ?>
                <?php
                $stepNumber = $index + 1;
                $isFirst = $index === 0;
                $isLast = $stepNumber === $stepCount;
                $collapseId = 'etStepCollapse' . $stepNumber;
                $headingId = 'etStepHeading' . $stepNumber;
                $section = $group['section'];
                $stepLabel = ($section !== null && !empty($section['label']))
                    ? (string)$section['label']
                    : __('Details');
                $stepHelp = ($section !== null && !empty($section['help']))
                    ? (string)$section['help']
                    : '';
                // How much of this step the reporter cannot skip.
                $mandatoryCount = 0;
                foreach ($group['children'] as $child) {
                    if (!empty($child['mandatory'])) {
                        $mandatoryCount++;
                    }
                }
                ?>
                <div class="accordion-item et-step-item et-section-group border mb-2 rounded shadow-sm"
                     data-et-step="<?= $stepNumber ?>">
                    <h2 class="accordion-header" id="<?= $headingId ?>">
                        <button class="accordion-button rounded<?= $isFirst ? '' : ' collapsed' ?>"
                                type="button"
                                data-bs-toggle="collapse"
                                data-bs-target="#<?= $collapseId ?>"
                                aria-expanded="<?= $isFirst ? 'true' : 'false' ?>"
                                aria-controls="<?= $collapseId ?>">
                            <span class="badge bg-primary me-2"><?= $stepNumber ?></span>
                            <span class="fw-semibold"><?= h($stepLabel) ?></span>
                            <?php if ($mandatoryCount > 0): ?>
                                <span class="badge bg-warning-subtle text-warning-emphasis
                                             border border-warning-subtle ms-2"
                                      title="<?= h(__('Mandatory fields in this step')) ?>"
                                      style="font-size:.6rem;">
                                    <i class="fas fa-asterisk me-1"></i><?= $mandatoryCount ?>
                                </span>
                            <?php endif; ?>
                            <i class="fas fa-circle-check text-success ms-2 et-step-done-icon"
                               title="<?= h(__('Every mandatory field in this step is filled')) ?>"></i>
                        </button>
                    </h2>
                    <div id="<?= $collapseId ?>"
                         class="accordion-collapse collapse<?= $isFirst ? ' show' : '' ?>"
                         aria-labelledby="<?= $headingId ?>"
                         data-bs-parent="#etStepAccordion">
                        <div class="accordion-body et-section-body">

                            <?php if ($stepHelp !== ''): ?>
                                <div class="et-section-help text-muted small mb-3">
                                    <?= $this->EventTemplateMarkdown->render($stepHelp) ?>
                                </div>
                            <?php endif; ?>

                            <?php foreach ($group['children'] as $child): ?>
                                <?= $this->element('eventTemplates/userForm/' . $child['type'], [
                                    'element' => $child,
                                    'objectRelationSpecs' => $specs,
                                ]) ?>
                            <?php endforeach; ?>

                            <!-- Step navigation, SharingGroups/add style -->
                            <div class="d-flex justify-content-between align-items-center mt-3 pt-3"
                                 style="border-top:1px dashed var(--bs-border-color, #dee2e6);">
                                <?php if ($isFirst): ?>
                                    <span class="text-muted" style="font-size:.75rem;">
                                        <?= __('Step %1$s of %2$s', $stepNumber, $stepCount) ?>
                                    </span>
                                <?php else: ?>
                                    <button type="button" class="btn btn-outline-secondary btn-sm et-step-prev"
                                            data-et-target="#etStepCollapse<?= $stepNumber - 1 ?>">
                                        <i class="fas fa-chevron-up me-1"></i><?= __('Previous') ?>
                                    </button>
                                <?php endif; ?>

                                <?php if (!$isLast): ?>
                                    <button type="button" class="btn btn-primary btn-sm et-step-next"
                                            data-et-target="#etStepCollapse<?= $stepNumber + 1 ?>">
                                        <?= __('Next') ?><i class="fas fa-chevron-down ms-1"></i>
                                    </button>
                                <?php else: ?>
                                    <span class="text-muted" style="font-size:.75rem;">
                                        <?= __('Last step — create the event below.') ?>
                                    </span>
                                <?php endif; ?>
                            </div>

                        </div>
                    </div>
                </div>
            <?php endforeach; ?>
        </div>

        <!-- ── FOOTER ─────────────────────────────────────────── -->
        <div class="et-save-bar d-flex justify-content-between align-items-center
                    mt-4 pt-3 flex-wrap gap-2"
             style="border-top:1px solid var(--bs-border-color, #dee2e6);">
            <div class="d-flex align-items-center gap-3 flex-wrap text-muted"
                 style="font-size:.75rem;">
                <span id="et-step-progress"
                      data-et-label="<?= h(__('Step %1$s of %2$s')) ?>"
                      data-et-total="<?= $stepCount ?>">
                    <?= $stepCount > 0 ? __('Step %1$s of %2$s', 1, $stepCount) : '' ?>
                </span>
                <span id="et-user-form-status"></span>
            </div>
            <div class="d-flex gap-2">
                <?php if ($isModal): ?>
                    <button type="button" class="btn btn-outline-secondary btn-sm"
                            data-bs-dismiss="modal">
                        <i class="fas fa-times me-1"></i><?= __('Discard') ?>
                    </button>
                <?php else: ?>
                    <a class="btn btn-outline-secondary btn-sm"
                       href="<?= h($isPreview
                            ? $baseurl . '/event_templates/view/' . $templateId
                            : $baseurl . '/event_templates/index') ?>">
                        <i class="fas fa-times me-1"></i>
                        <?= $isPreview ? __('Back to template') : __('Cancel') ?>
                    </a>
                <?php endif; ?>

                <?php if ($isPreview): ?>
                    <button type="button" class="btn btn-secondary btn-sm" disabled>
                        <i class="fas fa-bolt me-1"></i><?= __('Create event (disabled in preview)') ?>
                    </button>
                <?php else: ?>
                    <button type="button" id="et-user-form-submit" class="btn btn-primary btn-sm">
                        <i class="fas fa-bolt me-1"></i><?= __('Create event') ?>
                    </button>
                <?php endif; ?>
            </div>
        </div>
    </form>
</div>

<?php
    // JSON_HEX_TAG / AMP / APOS / QUOT harden against HTML5 script-data
    // state-machine quirks for any DB-sourced strings landing here.
    $jsonScriptFlags = JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT;
?>


<script>

    window.ET_USER_FORM_CONFIG = {
        baseurl:    <?= json_encode($baseurl, $jsonScriptFlags) ?>,
        templateId: <?= (int)$templateId ?>,
        isPreview:  <?= $isPreview ? 'true' : 'false' ?>,
        eventViewUrl: <?= json_encode($baseurl . '/events/view2/', $jsonScriptFlags) ?>
    };
</script>



<?php
    echo $this->element('genericElements/assetLoader', [
        'js' => [
            'event-templates/user_form',
            'event-templates/user_form_overmind',
        ],
    ]);
?>



<script>
/*
 * Step navigation + progress. Bootstrap's accordion already keeps a single step
 * open (data-bs-parent); this only adds the Previous/Next buttons, the footer
 * counter, and the green tick on steps whose mandatory fields are answered.
 */
(function () {
    var root = document.querySelector('.event-template-user-form');
    var accordion = document.getElementById('etStepAccordion');
    if (!root || !accordion) { return; }

    var items = Array.prototype.slice.call(
        accordion.querySelectorAll('.et-step-item')
    );
    var progress = document.getElementById('et-step-progress');
    var total = items.length;

    function show(selector) {
        var target = accordion.querySelector(selector);
        if (target && window.bootstrap) {
            bootstrap.Collapse.getOrCreateInstance(target, {toggle: false}).show();
        }
    }

    accordion.addEventListener('click', function (e) {
        var btn = e.target.closest('.et-step-next, .et-step-prev');
        if (!btn) { return; }
        show(btn.getAttribute('data-et-target'));
    });

    function currentStep() {
        for (var i = 0; i < items.length; i++) {
            if (items[i].querySelector('.accordion-collapse.show')) { return i + 1; }
        }
        return 0;
    }

    function renderProgress() {
        if (!progress || !total) { return; }
        var step = currentStep() || 1;
        var label = progress.getAttribute('data-et-label') || 'Step %1$s of %2$s';
        progress.textContent = label
            .replace('%1$s', step)
            .replace('%2$s', total);
    }

    /*
     * A step is done when none of its mandatory fields is flagged as missing.
     * The flags are user_form.js's own verdict
     */
    function refreshDoneState() {
        items.forEach(function (item) {
            var fields = item.querySelectorAll('.et-field[data-et-mandatory="1"]');
            var done = fields.length > 0;
            Array.prototype.forEach.call(fields, function (field) {
                if (field.classList.contains('et-missing')
                    || field.querySelector('.et-value.et-invalid')) {
                    done = false;
                }
            });
            if (item.classList.contains('et-step-done') !== done) {
                item.classList.toggle('et-step-done', done);
            }
        });
    }

    accordion.addEventListener('shown.bs.collapse', renderProgress);
    accordion.addEventListener('hidden.bs.collapse', renderProgress);

    var form = document.getElementById('et-user-form');
    if (form && window.MutationObserver) {
        new MutationObserver(function (records) {
            var relevant = records.some(function (record) {
                return !(record.target.classList
                    && record.target.classList.contains('et-step-item'));
            });
            if (relevant) { refreshDoneState(); }
        }).observe(form, {
            attributes: true,
            attributeFilter: ['class'],
            subtree: true
        });
    }

    renderProgress();
    refreshDoneState();
}());
</script>
