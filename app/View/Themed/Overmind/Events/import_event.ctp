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

<!-- ── MODAL HEADER ─────────────────────────────────────────── -->
<div class="px-4 pt-3 pb-3 d-flex align-items-center justify-content-between"
     style="background:rgba(24,146,177,.06);
            border-bottom:2px solid var(--event, var(--primary));">
    <div>
        <div class="text-event text-uppercase fw-semibold mb-1"
             style="font-size:.58rem; letter-spacing:.12em; opacity:.85;">
            <?= __('Events') ?>
        </div>
        <h4 class="mb-0 fw-bold d-flex align-items-center gap-2">
            <i class="fas fa-circle-plus text-event" style="font-size:1.25rem;"></i>
            <?= __('Import Event') ?>
        </h4>
        <p class="text-muted mb-0" style="font-size:.75rem;">
            <?= __('Create one or more events by importing an existing MISP export or STIX document.') ?>
        </p>
    </div>
    <span class="fas fa-file-import text-event"
          style="font-size:2rem; opacity:.5;"></span>
</div>

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
        <p class="text-muted small mb-2">
            <?= __('Recommended exchange format. Paste the file content or upload a MISP XML / JSON export.') ?>
        </p>
        <div class="mb-3">
            <label class="form-label fw-semibold" for="mispFileContent">
                <?= __('Paste MISP XML or JSON file content') ?>
            </label>
            <?= $this->Form->textarea('filecontent', [
                'class' => 'form-control font-monospace',
                'id' => 'mispFileContent',
                'rows' => 6,
                'placeholder' => '{ "Event": { … } }',
            ]) ?>
        </div>
        <div class="mb-3">
            <label class="form-label fw-semibold" for="mispSubmittedFile">
                <?= __('…or choose a MISP XML / JSON file') ?>
            </label>
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
                <div class="form-text">
                    <?= __('Warning: this changes the creator organisation of the event and can lead to unexpected behaviour when synchronising with instances that have another creator for the same event.') ?>
                </div>
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
        <div class="mb-3">
            <label class="form-label fw-semibold" for="mispSignature">
                <?= __('Protected event signature') ?>
            </label>
            <?= $this->Form->textarea('signature', [
                'class' => 'form-control font-monospace',
                'id' => 'mispSignature',
                'rows' => 2,
                'placeholder' => __('Paste the b64 encoded key here if applicable.'),
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
            <label class="form-label fw-semibold" for="<?= $p ?>StixFile">
                <?= __('STIX %s file', $stix['version']) ?>
            </label>
            <?= $this->Form->file('stix', [
                'class' => 'form-control',
                'id' => $p . 'StixFile',
            ]) ?>
        </div>

        <div class="row g-3">
            <div class="col-md-6">
                <label class="form-label fw-semibold" for="<?= $p ?>Distribution">
                    <?= __('Distribution') ?>
                </label>
                <?= $this->Form->select('distribution', $distributionLevels, [
                    'class' => 'form-select',
                    'id' => $p . 'Distribution',
                    'value' => $initialDistribution,
                ]) ?>
            </div>
            <div class="col-md-6<?= $initialDistribution === 4 ? '' : ' d-none' ?>"
                 id="<?= $p ?>SgContainer">
                <label class="form-label fw-semibold" for="<?= $p ?>SharingGroup">
                    <?= __('Sharing Group') ?>
                </label>
                <?= $this->Form->select('sharing_group_id', $sharingGroups, [
                    'class' => 'form-select tom-select',
                    'id' => $p . 'SharingGroup',
                    'empty' => __('Select a sharing group…'),
                ]) ?>
            </div>
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

        <div class="mt-3">
            <label class="form-label fw-semibold" for="<?= $p ?>ForceContextual">
                <?= __('How to convert contextual STIX objects') ?>
            </label>
            <?= $this->Form->select('force_contextual_data', $forceContextualDataOptions, [
                'class' => 'form-select',
                'id' => $p . 'ForceContextual',
                'value' => 1,
            ]) ?>
            <div class="form-text"><?= h($forceContextualDataDescriptions[1]) ?></div>
        </div>

        <?php if ($canGalaxyHandling): ?>
            <div class="mt-3">
                <label class="form-label fw-semibold" for="<?= $p ?>GalaxiesHandling">
                    <?= __('How to handle Galaxies and Clusters') ?>
                </label>
                <?= $this->Form->select('galaxies_handling', $galaxiesOptions, [
                    'class' => 'form-select',
                    'id' => $p . 'GalaxiesHandling',
                    'value' => 0,
                ]) ?>
                <div class="form-text"><?= h($galaxiesOptionsDescriptions[0]) ?></div>
            </div>
            <div class="row g-3 mt-0" id="<?= $p ?>ClusterDistWrap">
                <div class="col-md-6">
                    <label class="form-label fw-semibold" for="<?= $p ?>ClusterDistribution">
                        <?= __('Cluster distribution') ?>
                    </label>
                    <?= $this->Form->select('cluster_distribution', $distributionLevels, [
                        'class' => 'form-select',
                        'id' => $p . 'ClusterDistribution',
                        'value' => $initialDistribution,
                    ]) ?>
                </div>
                <div class="col-md-6 d-none" id="<?= $p ?>ClusterSgContainer">
                    <label class="form-label fw-semibold" for="<?= $p ?>ClusterSharingGroup">
                        <?= __('Cluster Sharing Group') ?>
                    </label>
                    <?= $this->Form->select('cluster_sharing_group_id', $sharingGroups, [
                        'class' => 'form-select',
                        'id' => $p . 'ClusterSharingGroup',
                        'empty' => __('Select a sharing group…'),
                    ]) ?>
                </div>
            </div>
        <?php endif; ?>

        <?php if ($canDebug): ?>
            <div class="mt-3">
                <label class="form-label fw-semibold" for="<?= $p ?>Debug">
                    <?= __('Debugging option') ?>
                </label>
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

    <!-- ── FOOTER ─────────────────────────────────────────────── -->
    <div class="d-flex justify-content-end align-items-center mt-4 pt-3 flex-wrap gap-2"
         style="border-top:1px solid var(--bs-border-color, #dee2e6);">
        <button type="button" class="btn btn-outline-secondary btn-sm"
                data-bs-dismiss="modal">
            <i class="fas fa-times me-1"></i><?= __('Discard') ?>
        </button>
    </div>
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
    function showImportSpinner() {
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

    // STIX 1.x / 2.x share the same wiring, keyed by prefix.
    ['s1', 's2'].forEach(function (p) {
        var sg = byId(p + 'SgContainer');
        if (byId(p + 'Distribution') && typeof initDistributionSelect === 'function') {
            initDistributionSelect(p + 'Distribution', function (val) {
                if (sg) { sg.classList.toggle('d-none', String(val) !== '4'); }
            });
        }

        var galEl = byId(p + 'GalaxiesHandling');
        var clWrap = byId(p + 'ClusterDistWrap');
        var clDist = byId(p + 'ClusterDistribution');
        var clSg = byId(p + 'ClusterSgContainer');
        function syncCluster() {
            var galVal = galEl ? galEl.value : '1';
            if (clWrap) { clWrap.classList.toggle('d-none', String(galVal) !== '0'); }
            var clVal = clDist ? clDist.value : '0';
            if (clSg) {
                clSg.classList.toggle('d-none', !(String(galVal) === '0' && String(clVal) === '4'));
            }
        }
        if (galEl) { galEl.addEventListener('change', syncCluster); }
        if (clDist) { clDist.addEventListener('change', syncCluster); }
        syncCluster();

        // Require a STIX file before submitting.
        requireAny(byId(p + 'Form'), [byId(p + 'StixFile')]);
    });
})();
</script>
