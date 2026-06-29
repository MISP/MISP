<?php
/**
 * Each accordion section is a self-contained <form> that posts (full page) to its own legacy import action 
 *
 * Cross-action POST works because each form sets its `url` explicitly, so the
 * Security token's `_lastAction` (render side) matches request->here()
 * (receive side).
 *
 * Available vars: $id (event id), $event, $importModules.
 */

$eventId = (int)$id;

/**
 * Render the opening markup of one accordion section.
 * The caller writes the section body (its form) then closeSection().
 */
$openSection = function ($num, $collapseId, $icon, $title, $subtitle, $open = false) {
    $btnClass = 'accordion-button rounded' . ($open ? '' : ' collapsed');
    $collapseClass = 'accordion-collapse collapse' . ($open ? ' show' : '');
    ?>
    <div class="accordion-item border mb-2 rounded shadow-sm">
        <h2 class="accordion-header" id="heading<?= h($collapseId) ?>">
            <button class="<?= $btnClass ?>" type="button"
                    data-bs-toggle="collapse"
                    data-bs-target="#<?= h($collapseId) ?>"
                    aria-expanded="<?= $open ? 'true' : 'false' ?>"
                    aria-controls="<?= h($collapseId) ?>">
                <i class="<?= h($icon) ?> me-2 text-muted"></i>
                <span class="fw-semibold"><?= h($title) ?></span>
                <span class="text-muted ms-2 small d-none d-sm-inline"><?= h($subtitle) ?></span>
            </button>
        </h2>
        <div id="<?= h($collapseId) ?>"
             class="<?= $collapseClass ?>"
             aria-labelledby="heading<?= h($collapseId) ?>"
             data-bs-parent="#populateFromAccordion">
            <div class="accordion-body">
    <?php
};
$closeSection = function () {
    ?>
            </div>
        </div>
    </div>
    <?php
};

/** Right-aligned submit button used at the bottom of each form. */
$submitRow = function ($label, $icon = 'fas fa-sign-in-alt', $class = 'btn-primary') {
    ?>
    <div class="d-flex justify-content-end mt-3">
        <button type="submit" class="btn <?= h($class) ?>">
            <i class="<?= h($icon) ?> me-1"></i><?= h($label) ?>
        </button>
    </div>
    <?php
};
?>

<!-- ── MODAL HEADER ─────────────────────────────────────────── -->
<div class="px-4 pt-3 pb-3 d-flex align-items-center justify-content-between"
     style="background:rgba(24,146,177,.06);
            border-bottom:2px solid var(--event);">
    <div>
        <div class="text-event text-uppercase fw-semibold mb-1"
             style="font-size:.58rem; letter-spacing:.12em; opacity:.85;">
            <?= __('Events') ?>
        </div>
        <h4 class="mb-0 fw-bold d-flex align-items-center gap-2">
            <i class="fas fa-circle-plus text-event" style="font-size:1.25rem;"></i>
            <?= __('Populate from…') ?>
        </h4>
    </div>
    <span class="fas fa-sign-in-alt text-event"
          style="font-size:2rem; opacity:.5;"></span>
</div>

<!-- ── BODY ─────────────────────────────────────────────────── -->
<div class="p-4">
    <p class="text-muted mb-3">
        <?= __('Choose an import method below. Each section is independent — fill it in and submit it on its own.') ?>
    </p>

    <div class="accordion" id="populateFromAccordion">

        <?php
        // ===================== 1. MISP JSON =====================
        $openSection(1, 'pfJson', 'fas fa-code', __('MISP JSON'), __('Paste MISP event JSON'));
        echo $this->Form->create('Event', [
            'url' => $baseurl . '/events/populate/' . $eventId,
            'id' => 'populateJsonForm',
        ]);
        ?>
        <p class="text-muted small mb-2">
            <?= __('Populate the event using a JSON document containing MISP event content data.') ?>
        </p>
        <div class="mb-3">
            <label class="form-label fw-semibold" for="PopulateEventJson"><?= __('JSON') ?></label>
            <?= $this->Form->textarea('Event.json', [
                'class' => 'form-control font-monospace',
                'id' => 'PopulateEventJson',
                'rows' => 10,
                'placeholder' => '{ "Event": { … } }',
            ]) ?>
        </div>
        <div class="form-check mb-2">
            <?= $this->Form->checkbox('Event.regenerate_uuids', [
                'class' => 'form-check-input',
                'id' => 'PopulateRegenUuids',
                'hiddenField' => true,
            ]) ?>
            <label class="form-check-label" for="PopulateRegenUuids">
                <?= __('Regenerate UUIDs') ?>
            </label>
            <div class="form-text">
                <?= __('Assign fresh UUIDs to imported attributes and objects instead of keeping the ones from the JSON.') ?>
                </br>
                <?= __('If the UUIDs are already in use, the attributes will not be created') ?>
            </div>
        </div>
        <?php $submitRow(__('Populate from JSON'), 'fas fa-code'); ?>
        <?= $this->Form->end(); ?>
        <?php $closeSection(); ?>

        <?php
        // ===================== 2. FREETEXT =====================
        $openSection(2, 'pfFreetext', 'fas fa-paragraph', __('Freetext Import'), __('Auto-detect IOCs from text'));
        echo $this->Form->create('MispAttribute', [
            'url' => $baseurl . '/events/freeTextImport/' . $eventId,
            'id' => 'populateFreetextForm',
        ]);
        echo $this->Form->hidden('Attribute.event_id', ['value' => $eventId]);
        ?>
        <p class="text-muted small mb-2">
            <?= __('Paste a list of IOCs into the field below for automatic detection. You will then review the resolved attributes before saving.') ?>
        </p>
        <div class="mb-3">
            <label class="form-label fw-semibold" for="PopulateFreetextValue"><?= __('IOCs') ?></label>
            <?= $this->Form->textarea('Attribute.value', [
                'class' => 'form-control',
                'id' => 'PopulateFreetextValue',
                'rows' => 8,
                'placeholder' => "8.8.8.8\nexample.com\nd41d8cd98f00b204e9800998ecf8427e",
            ]) ?>
        </div>
        <?php $submitRow(__('Run Freetext Import'), 'fas fa-paragraph'); ?>
        <?= $this->Form->end(); ?>
        <?php $closeSection(); ?>

        <?php
        // ===================== 3. Forensic analysis (Mactime) =====================
        $openSection(6, 'pfForensic', 'fas fa-microscope', __('Forensic analysis'), __('Mactime'));
        echo $this->Form->create('Event', [
            'url' => $baseurl . '/events/upload_analysis_file/' . $eventId,
            'type' => 'file',
            'id' => 'populateForensicForm',
        ]);
        ?>
        <p class="text-muted small mb-2">
            <?= __('Upload a Mactime analysis file. You will then select the lines to turn into objects.') ?>
        </p>
        <div class="mb-3">
            <label class="form-label fw-semibold" for="PopulateAnalysisFile"><?= __('Analysis file') ?></label>
            <?= $this->Form->file('Event.analysis_file', [
                'class' => 'form-control',
                'id' => 'PopulateAnalysisFile',
            ]) ?>
        </div>
        <?php $submitRow(__('Upload analysis file'), 'fas fa-upload'); ?>
        <?= $this->Form->end(); ?>
        <?php $closeSection(); ?>

        <?php
        // ===================== 7+. Import modules (one launcher section per enabled module) =====================
        if (empty($importModules)):
            $openSection(7, 'pfNoModules', 'fas fa-puzzle-piece', __('Import modules'), __('Enabled import modules'));
            ?>
            <div class="alert alert-light border mb-0">
                <?= __('No import module is enabled.') ?>
            </div>
            <?php
            $closeSection();
        else:
            foreach ($importModules as $i => $module):
                $openSection(7 + $i, 'pfMod' . $i, 'fas fa-puzzle-piece', $module['text'], __('Import module'));
                ?>
                <p class="text-muted small mb-2">
                    <?= __('Open the import form for this module in a new dialog.') ?>
                </p>
                <div class="d-flex justify-content-end mt-3">
                    <button type="button" class="btn btn-primary"
                            onclick="openModalChained('<?= $baseurl ?>/events/importModule/<?= h($module['name']) ?>/<?= $eventId ?>');">
                        <i class="fas fa-up-right-from-square me-1"></i><?= __('Open module') ?>
                    </button>
                </div>
                <?php
                $closeSection();
            endforeach;
        endif;
        ?>

    </div>

    <!-- ── FOOTER ─────────────────────────────────────────────── -->
    <div class="d-flex justify-content-between align-items-center mt-4 pt-3 flex-wrap gap-2"
         style="border-top:1px solid var(--bs-border-color, #dee2e6);">
        <div class="text-muted" style="font-size:.75rem;">
            <?= __('Event') ?>:
            <strong class="text-body">#<?= h($eventId) ?></strong>
        </div>
        <div class="d-flex gap-2">
            <button type="button" class="btn btn-outline-secondary btn-sm"
                    data-bs-dismiss="modal">
                <i class="fas fa-times me-1"></i><?= __('Discard') ?>
            </button>
        </div>
    </div>
</div>

<script>
(function () {
    // Submit a populate sub-form via fetch and show its result in a chained modal
    function wireModalForm(id) {
        var form = document.getElementById(id);
        if (!form) { return; }
        form.addEventListener('submit', function (e) {
            e.preventDefault();
            openModalPostChained(form.getAttribute('action'), new FormData(form));
        });
    }
    // Freetext: pasted IOCs → resolution screen.
    wireModalForm('populateFreetextForm');
    // Forensic: uploaded Mactime file → timeline selection screen.
    wireModalForm('populateForensicForm');

    // Keep each section's submit button disabled until its required input is provided
    function requireInput(formId, inputId, isFile) {
        var form = document.getElementById(formId);
        var input = document.getElementById(inputId);
        if (!form || !input) { return; }
        var btn = form.querySelector('button[type="submit"]');
        if (!btn) { return; }
        function check() {
            var ok = isFile ? (input.files && input.files.length > 0)
                            : (input.value.trim() !== '');
            btn.disabled = !ok;
        }
        input.addEventListener(isFile ? 'change' : 'input', check);
        check();
    }
    requireInput('populateJsonForm',     'PopulateEventJson');
    requireInput('populateFreetextForm', 'PopulateFreetextValue');
    requireInput('populateForensicForm', 'PopulateAnalysisFile', true);
})();
</script>
