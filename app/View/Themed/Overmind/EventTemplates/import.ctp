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
<?= $this->element('genericElementsBS5/Forms/modal_header', [
    'accent' => 'event',
    'eyebrow' => __('Event Templates'),
    'title' => __('Import Event Template'),
    'description' => $headerDescription,
    'icon' => 'fas fa-file-import',
]) ?>
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
            <?= $this->element('genericElementsBS5/Forms/field_hint', [
                'text' => __('The export document of any MISP instance running the same template schema.'),
            ]) ?>
        </div>

        <!-- ── JSON FILE ───────────────────────────────────────── -->
        <div class="w-100 px-2">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'accent' => 'primary',
                'label' => __('Or Upload a JSON File'),
            ]) ?>
            <?= $this->Form->file('submittedjson', [
                'class' => 'form-control bg-light',
                'accept' => 'application/json,.json',
            ]) ?>
            <?= $this->element('genericElementsBS5/Forms/field_hint', [
                'text' => __('Optional — if both a pasted document and a file are provided, the file wins.'),
            ]) ?>
        </div>

        <!-- ── DUPLICATE HANDLING ──────────────────────────────── -->
        <div class="w-100 px-2">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'accent' => 'primary',
                'label' => __('If a Template With the Same UUID Already Exists'),
            ]) ?>
            <?= $this->Form->select('mode', $modeOptions, [
                'class' => 'form-select tom-select bg-light',
                'default' => 'fail',
                'empty' => false,
            ]) ?>
        </div>

    </div>

    <?= $this->element('genericElementsBS5/Forms/modal_footer', [
        'hint' => __('The import is refused whole if any element fails validation.'),
        'cancel' => $isModal ? [] : [
            'label' => __('Cancel'),
            'href' => $baseurl . '/event_templates/index',
            'attrs' => [],
        ],
        'submit' => ['label' => __('Import'), 'icon' => 'fas fa-upload'],
    ]) ?>
</div>

<?= $this->Form->end() ?>
