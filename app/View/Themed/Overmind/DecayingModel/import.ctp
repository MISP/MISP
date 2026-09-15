<?php
$isModal = !empty($ajax);

$headerDescription = __(
    'Paste a MISP decaying-model JSON below, or provide a JSON file.'
    . 'The imported model is added to your organisation as a non-default model.'
);

echo $this->Form->create('DecayingModel', [
    'enctype' => 'multipart/form-data',
    'class' => 'needs-validation',
    'novalidate' => true,
]);
?>

<?php if ($isModal): ?>
<?= $this->element('genericElementsBS5/Forms/modal_header', [
    'accent' => 'primary',
    'eyebrow' => __('Decaying Models'),
    'title' => __('Import Decaying Model'),
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

        <!-- ── Decaying Model DOCUMENT ───────────────────────────────── -->
        <div class="w-100 px-2">
            <div class="d-flex align-items-center gap-2 text-primary fw-bold
                        text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('Decaying Model JSON') ?>
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
                    '{ "name": "...", "formula": "Polynomial", "parameters": { ... } }'
                ),
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

    </div>

    <?= $this->element('genericElementsBS5/Forms/modal_footer', [
        'hint' => __('The import is refused whole if any element fails validation.'),
        'cancel' => $isModal ? [] : [
            'label' => __('Cancel'),
            'href' => $baseurl . '/decayingModel/index',
            'attrs' => [],
        ],
        'submit' => ['label' => __('Import'), 'icon' => 'fas fa-upload'],
    ]) ?>
</div>

<?= $this->Form->end() ?>