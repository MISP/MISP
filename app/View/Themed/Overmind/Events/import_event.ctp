<?php
/**
 * Overmind combined "Import Event" modal.
 *
 * Reuses the Add-Event modal look and offers the three legacy event-import
 * entry points as independent accordion sections. Each section is a
 * self-contained <form> that posts (full page) to its own legacy action:
 *   1. MISP export file  -> /events/add_misp_export
 *   2. STIX 1.x          -> /events/upload_stix
 *   3. STIX 2.x          -> /events/upload_stix/2
 *
 * Cross-action POST works because each form sets its `url` explicitly, so the
 * Security token's `_lastAction` (render side) matches request->here()
 * (receive side) — same pattern as populate_from.ctp.
 *
 * Available vars: $distributionLevels, $sharingGroups, $initialDistribution,
 * $forceContextualDataOptions, $forceContextualDataDescriptions,
 * $galaxiesOptions, $galaxiesOptionsDescriptions, $debugOptions.
 * Globals: $baseurl, $me, $isAclPublish.
 */

$initialDistribution = (int)$initialDistribution;
$canGalaxyHandling = !empty($me['Role']['perm_site_admin']) || !empty($me['Role']['perm_galaxy_editor']);
$canDebug = !empty($me['Role']['perm_site_admin']) && Configure::read('debug') > 0;

/** Opening markup of one accordion section. Caller writes the body then closeSection(). */
$openSection = function ($collapseId, $icon, $title, $subtitle, $open = false) {
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
             data-bs-parent="#importEventAccordion">
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

/** Right-aligned submit button at the bottom of each form. */
$submitRow = function ($label, $icon = 'fas fa-file-import') {
    ?>
    <div class="d-flex justify-content-end mt-3">
        <button type="submit" class="btn btn-primary">
            <i class="<?= h($icon) ?> me-1"></i><?= h($label) ?>
        </button>
    </div>
    <?php
};
?>

<?= $this->element('genericElementsBS5/Forms/modal_header', [
    'accent' => 'event',
    'eyebrow' => __('Events'),
    'title' => __('Import Event'),
    'description' => __('Create one or more events by importing an existing MISP export or STIX document.'),
    'icon' => 'fas fa-file-import',
]) ?>

<!-- ── BODY ─────────────────────────────────────────────────── -->
<div class="p-4">
    <div id="importEventInteractive">
    <p class="text-muted mb-3">
        <?= __('Pick an import format below. Each section is independent — fill it in and submit it on its own.') ?>
    </p>

    <div class="accordion" id="importEventAccordion">

        <?php
        // ===================== 1. MISP EXPORT FILE =====================
        $openSection('impMisp', 'fas fa-file-code', __('MISP Export File'), __('XML or JSON — lossless'), true);
        echo $this->Form->create('Event', [
            'type' => 'file',
            'url' => $baseurl . '/events/add_misp_export',
            'id' => 'importMispForm',
        ]);
        ?>
        <p class="text-muted small mb-3">
            <?= __('Recommended exchange format. Paste the file content or upload a MISP XML / JSON export.') ?>
        </p>

        <div class="mb-3">
            <?= $this->element('genericElementsBS5/Forms/json_field', [
                'field' => 'filecontent',
                'accent' => 'event',
                'label' => __('Paste a MISP export'),
                'xml' => true,
                'id' => 'mispFileContent',
                'rows' => 8,
                'minHeight' => '200px',
                'emptyLabel' => __('Nothing pasted'),
                'placeholder' => "{\n    \"Event\": {\n        \"info\": \"…\",\n        \"Attribute\": []\n    }\n}",
                'hint' => __('A MISP JSON or XML export document — or leave it empty and pick the file below.'),
            ]) ?>
        </div>

        <div class="mb-3">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'accent' => 'event',
                'label' => __('…or choose a MISP XML / JSON file'),
                'for' => 'mispSubmittedFile',
            ]) ?>
            <?= $this->Form->file('submittedfile', [
                'class' => 'form-control',
                'id' => 'mispSubmittedFile',
                'accept' => '.xml,.json',
            ]) ?>
        </div>
        <?php if (Configure::read('MISP.take_ownership_xml_import')): ?>
            <div class="form-check mb-2">
                <?= $this->Form->checkbox('takeownership', [
                    'class' => 'form-check-input',
                    'id' => 'mispTakeOwnership',
                    'hiddenField' => true,
                ]) ?>
                <label class="form-check-label" for="mispTakeOwnership">
                    <?= __('Take ownership of the event') ?>
                </label>
                <?= $this->element('genericElementsBS5/Forms/field_hint', [
                    'icon' => 'fas fa-triangle-exclamation mt-1',
                    'text' => __('This changes the creator organisation of the event, and can lead to unexpected behaviour when synchronising with instances that have another creator for the same event.'),
                ]) ?>
            </div>
        <?php endif; ?>
        <?php if (!empty($isAclPublish)): ?>
            <div class="form-check mb-2">
                <?= $this->Form->checkbox('publish', [
                    'class' => 'form-check-input',
                    'id' => 'mispPublish',
                    'hiddenField' => true,
                ]) ?>
                <label class="form-check-label" for="mispPublish">
                    <?= __('Publish imported events') ?>
                </label>
            </div>
        <?php endif; ?>
        <div class="mb-3 mt-3">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'accent' => 'event',
                'label' => __('Protected event signature'),
                'for' => 'mispSignature',
            ]) ?>
            <?= $this->Form->textarea('signature', [
                'class' => 'form-control font-monospace',
                'id' => 'mispSignature',
                'rows' => 2,
                'placeholder' => __('Paste the b64 encoded key here if applicable.'),
            ]) ?>
            <?= $this->element('genericElementsBS5/Forms/field_hint', [
                'text' => __('Checked against the uploaded file only — a signature is not verified against pasted content.'),
            ]) ?>
        </div>
        <?php if (!empty(Configure::read('MISP.allow_users_override_locked_field_when_importing_events'))): ?>
            <div class="form-check mb-2">
                <?= $this->Form->checkbox('allow_lock_override', [
                    'class' => 'form-check-input',
                    'id' => 'mispAllowLockOverride',
                    'hiddenField' => true,
                ]) ?>
                <label class="form-check-label" for="mispAllowLockOverride">
                    <?= __('Allow lock override (locked state is set from the imported events)') ?>
                </label>
            </div>
        <?php endif; ?>
        <?php $submitRow(__('Import MISP file'), 'fas fa-file-code'); ?>
        <?= $this->Form->end(); ?>
        <?php $closeSection(); ?>

        <?php
        // ===================== 2. + 3. STIX 1.x / 2.x =====================
        $stixForms = [
            ['version' => '1.x', 'url' => $baseurl . '/events/upload_stix', 'prefix' => 's1',
             'icon' => 'fas fa-shield-halved', 'subtitle' => __('STIX 1.x XML — lossy')],
            ['version' => '2.x', 'url' => $baseurl . '/events/upload_stix/2', 'prefix' => 's2',
             'icon' => 'fas fa-shield-halved', 'subtitle' => __('STIX 2.x JSON — lossy')],
        ];
        foreach ($stixForms as $stix):
            $p = $stix['prefix'];
            $openSection('imp' . $p, $stix['icon'], __('STIX %s', $stix['version']), $stix['subtitle']);
            echo $this->Form->create('Event', [
                'type' => 'file',
                'url' => $stix['url'],
                'id' => $p . 'Form',
            ]);
        ?>
        <div class="mb-3">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'accent' => 'event',
                'label' => __('STIX %s file', $stix['version']),
                'required' => true,
                'for' => $p . 'StixFile',
            ]) ?>
            <?= $this->Form->file('stix', [
                'class' => 'form-control',
                'id' => $p . 'StixFile',
                'accept' => $stix['version'] === '1.x' ? '.xml' : '.json',
            ]) ?>
        </div>

        <div class="mt-3">
            <?= $this->element('genericElementsBS5/Forms/distribution_field', [
                'accent' => 'event',
                'compact' => true,
                'id' => $p . 'Distribution',
                'sgId' => $p . 'SharingGroup',
                'hint' => __('Applied to every event the document produces.'),
            ]) ?>
        </div>

        <div class="form-check mt-3">
            <?= $this->Form->checkbox('publish', [
                'class' => 'form-check-input',
                'id' => $p . 'Publish',
                'hiddenField' => true,
            ]) ?>
            <label class="form-check-label" for="<?= $p ?>Publish">
                <?= __('Publish imported events') ?>
            </label>
        </div>
        <div class="form-check">
            <?= $this->Form->checkbox('original_file', [
                'class' => 'form-check-input',
                'id' => $p . 'OriginalFile',
                'checked' => true,
                'hiddenField' => true,
            ]) ?>
            <label class="form-check-label" for="<?= $p ?>OriginalFile">
                <?= __('Include the original imported file as attachment') ?>
            </label>
        </div>

        <div class="mt-4">
            <?= $this->element('genericElementsBS5/Forms/choice_cards', [
                'field' => 'force_contextual_data',
                'accent' => 'event',
                'id' => $p . 'ForceContextual',
                'value' => 1,
                'columns' => 2,
                'ariaLabel' => __('How to convert contextual STIX objects'),
                'options' => [
                    [
                        'value' => 0,
                        'title' => $forceContextualDataOptions[0],
                        'sub' => $forceContextualDataDescriptions[0],
                        'icon' => 'fas fa-wand-magic-sparkles',
                    ],
                    [
                        'value' => 1,
                        'title' => $forceContextualDataOptions[1],
                        'sub' => $forceContextualDataDescriptions[1],
                        'icon' => 'fas fa-diagram-project',
                    ],
                ],
            ]) ?>
        </div>

        <?php if ($canGalaxyHandling): ?>
            <div class="mt-4">
                <?= $this->element('genericElementsBS5/Forms/choice_cards', [
                    'field' => 'galaxies_handling',
                    'accent' => 'galaxy',
                    'id' => $p . 'GalaxiesHandling',
                    'value' => 0,
                    'columns' => 2,
                    'ariaLabel' => __('How to handle Galaxies and Clusters'),
                    'reveal' => ['value' => 0, 'target' => '#' . $p . 'ClusterDistWrap'],
                    'options' => [
                        [
                            'value' => 0,
                            'title' => $galaxiesOptions[0],
                            'sub' => $galaxiesOptionsDescriptions[0],
                            'icon' => 'misp-icon misp-icon-galaxy misp-simple',
                        ],
                        [
                            'value' => 1,
                            'title' => $galaxiesOptions[1],
                            'sub' => $galaxiesOptionsDescriptions[1],
                            'icon' => 'fas fa-tag',
                        ],
                    ],
                ]) ?>
            </div>
            <div class="mt-3" id="<?= $p ?>ClusterDistWrap">
                <?= $this->element('genericElementsBS5/Forms/distribution_field', [
                    'field' => 'cluster_distribution',
                    'sgField' => 'cluster_sharing_group_id',
                    'accent' => 'galaxy',
                    'compact' => true,
                    'label' => __('Cluster Distribution'),
                    'id' => $p . 'ClusterDistribution',
                    'sgId' => $p . 'ClusterSharingGroup',
                    'sgLabel' => __('Cluster Sharing Group'),
                    'hint' => __('Applied to the clusters the document creates.'),
                ]) ?>
            </div>
        <?php endif; ?>

        <?php if ($canDebug): ?>
            <div class="mt-4">
                <?= $this->element('genericElementsBS5/Forms/section_label', [
                    'accent' => 'event',
                    'label' => __('Debugging option'),
                    'for' => $p . 'Debug',
                ]) ?>
                <?= $this->Form->select('debug', $debugOptions, [
                    'class' => 'form-select',
                    'id' => $p . 'Debug',
                    'value' => 0,
                ]) ?>
            </div>
        <?php endif; ?>

        <?php $submitRow(__('Import STIX %s', $stix['version']), 'fas fa-shield-halved'); ?>
        <?= $this->Form->end(); ?>
        <?php
            $closeSection();
        endforeach;
        ?>

    </div>

    <?= $this->element('genericElementsBS5/Forms/modal_footer', [
        'align' => 'end',
        'submit' => false,
    ]) ?>
    </div><!-- /#importEventInteractive -->

    <!-- ── IMPORT SPINNER (shown while a section is submitting) ──── -->
    <div id="importEventSpinner" class="d-none text-center py-5">
        <div class="spinner-border text-primary mb-3" role="status"
             style="width:3rem; height:3rem;">
            <span class="visually-hidden"><?= __('Loading…') ?></span>
        </div>
        <h5 class="fw-bold mb-1"><?= __('Import in progress…') ?></h5>
        <p class="text-muted mb-0" style="font-size:.85rem;">
            <?= __('Your data is being added. If you close this window, data will continue to be added.') ?>
        </p>
    </div>
</div>

<script>
(function () {
    function byId(id) { return document.getElementById(id); }

    // Enable a form's submit button only when a required control has a value.
    function requireAny(form, controls) {
        if (!form) { return; }
        var btn = form.querySelector('button[type="submit"]');
        if (!btn) { return; }
        function hasValue(el) {
            if (!el) { return false; }
            if (el.type === 'file') { return el.files && el.files.length > 0; }
            return el.value.trim() !== '';
        }
        function check() {
            btn.disabled = !controls.some(hasValue);
        }
        controls.forEach(function (el) {
            if (!el) { return; }
            el.addEventListener(el.type === 'file' ? 'change' : 'input', check);
        });
        check();
    }

    // On submit, swap the accordion (and footer) for a spinner + progress
    // message. We do NOT preventDefault — the full-page POST still proceeds;
    // hidden fields stay in the DOM so the in-flight submission is unaffected.
    //
    // The json_field guard runs first (it listens on the document in the
    // capture phase), so a document it refused is already marked here: hiding
    // the form then would leave a spinner running for an import that never
    // started.
    function showImportSpinner(e) {
        if (e.defaultPrevented) { return; }
        var interactive = byId('importEventInteractive');
        var spinner = byId('importEventSpinner');
        if (interactive) { interactive.classList.add('d-none'); }
        if (spinner) { spinner.classList.remove('d-none'); }
    }
    ['importMispForm', 's1Form', 's2Form'].forEach(function (id) {
        var form = byId(id);
        if (form) { form.addEventListener('submit', showImportSpinner); }
    });

    // MISP export: content pasted OR a file chosen.
    requireAny(byId('importMispForm'), [byId('mispFileContent'), byId('mispSubmittedFile')]);

    // Distribution, cluster distribution and the two card groups wire
    // themselves — distribution_field and choice_cards declare their own
    // reveals, and initChoiceFields() binds them. All that is left per
    // section is the file the endpoint cannot do without.
    ['s1', 's2'].forEach(function (p) {
        requireAny(byId(p + 'Form'), [byId(p + 'StixFile')]);
    });
})();
</script>
