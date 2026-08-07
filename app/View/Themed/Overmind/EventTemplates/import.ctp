<?php

$isModal = !empty($ajax);

$modeOptions = [
    'fail' => __('fail — abort the import (default)'),
    'overwrite' => __('overwrite — replace in place, preserve original ownership'),
    'duplicate_as_new' => __('duplicate_as_new — assign a fresh UUID and save as new'),
];

$importErrors = (isset($errors) && is_array($errors)) ? $errors : [];

$headerDescription = __(
    'Paste a previously-exported event template JSON, or upload a .json '
    . 'file. Imported templates become owned by your organisation unless '
    . 'you use the overwrite mode.'
);

if (!$isModal) {
    $this->set('headerTitle', __('Import Event Template'));
    $this->set('headerDescription', $headerDescription);
    // No paginator on this page — keep the count badge out of the header.
    $this->set('headerCountText', '');
}

echo $this->Form->create('EventTemplate', [
    'class' => 'needs-validation',
    'novalidate' => true,
    'enctype' => 'multipart/form-data',
    'url' => $baseurl . '/event_templates/import',
]);
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
            <i class="fas fa-circle-plus text-event" style="font-size:1.25rem;"></i>
            <?= __('Import Event Template') ?>
        </h4>
        <p class="text-muted mb-0" style="font-size:.75rem;">
            <?= h($headerDescription) ?>
        </p>
    </div>
    <span class="fas fa-file-import text-event"
          style="font-size:2rem; opacity:.5;"></span>
</div>
<?php endif; ?>

<div class="<?= $isModal ? 'p-4' : 'container-fluid px-4 py-3' ?>">

    <?php if (!empty($importErrors)): ?>
        <div class="alert alert-danger" role="alert">
            <strong><?= __('Could not import:') ?></strong>
            <ul class="mb-0">
                <?php foreach ($importErrors as $importError): ?>
                    <li><?= h($importError) ?></li>
                <?php endforeach; ?>
            </ul>
        </div>
    <?php endif; ?>

    <div class="d-flex flex-column gap-4">

        <!-- ── TEMPLATE DOCUMENT ───────────────────────────────── -->
        <div class="w-100 px-2">
            <div class="d-flex align-items-center gap-2 text-primary fw-bold
                        text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('Template Document') ?>
                <span class="badge bg-primary"
                      style="font-size:.55rem; opacity:.8; font-weight:700;">
                    <?= __('REQUIRED') ?>
                </span>
            </div>
            <?= $this->Form->textarea('json', [
                'class' => 'form-control bg-light font-monospace',
                'rows' => 14,
                'style' => 'font-size:.8rem;',
                'placeholder' => __(
                    'Paste the event template export document here'
                ),
            ]) ?>
            <div class="d-flex align-items-center gap-1 mt-1 text-muted"
                 style="font-size:.75rem;">
                <i class="fas fa-circle-info" style="font-size:.65rem;"></i>
                <?= __('The export document of any MISP instance running the same template schema.') ?>
            </div>
        </div>

        <!-- ── JSON FILE ───────────────────────────────────────── -->
        <div class="w-100 px-2">
            <div class="text-primary fw-bold text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('Or Upload a JSON File') ?>
            </div>
            <?= $this->Form->file('submittedjson', [
                'class' => 'form-control bg-light',
                'accept' => 'application/json,.json',
            ]) ?>
            <div class="d-flex align-items-center gap-1 mt-1 text-muted"
                 style="font-size:.75rem;">
                <i class="fas fa-circle-info" style="font-size:.65rem;"></i>
                <?= __('Optional — if both a pasted document and a file are provided, the file wins.') ?>
            </div>
        </div>

        <!-- ── DUPLICATE HANDLING ──────────────────────────────── -->
        <div class="w-100 px-2">
            <div class="text-primary fw-bold text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('If a Template With the Same UUID Already Exists') ?>
            </div>
            <?= $this->Form->select('mode', $modeOptions, [
                'class' => 'form-select tom-select bg-light',
                'default' => 'fail',
                'empty' => false,
            ]) ?>
        </div>

    </div>

    <!-- ── FOOTER ─────────────────────────────────────────────── -->
    <div class="d-flex justify-content-between align-items-center
                mt-4 pt-3 flex-wrap gap-2"
         style="border-top:1px solid var(--bs-border-color, #dee2e6);">
        <div class="text-muted" style="font-size:.75rem;">
            <i class="fas fa-shield-halved me-1"></i>
            <?= __('The import is refused whole if any element fails validation.') ?>
        </div>
        <div class="d-flex gap-2">
            <?php if ($isModal): ?>
                <button type="button" class="btn btn-outline-secondary btn-sm"
                        data-bs-dismiss="modal">
                    <i class="fas fa-times me-1"></i><?= __('Discard') ?>
                </button>
            <?php else: ?>
                <a class="btn btn-outline-secondary btn-sm"
                   href="<?= h($baseurl . '/event_templates/index') ?>">
                    <i class="fas fa-times me-1"></i><?= __('Cancel') ?>
                </a>
            <?php endif; ?>
            <?= $this->Form->button(
                '<i class="fas fa-upload me-1"></i> ' . __('Import'),
                [
                    'class' => 'btn btn-primary btn-sm',
                    'escapeTitle' => false,
                ]
            ) ?>
        </div>
    </div>
</div>

<?= $this->Form->end() ?>
