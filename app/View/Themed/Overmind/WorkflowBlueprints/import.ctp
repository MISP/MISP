<?php
$isModal = !empty($ajax);

$headerDescription = __(
    'Paste the JSON of a workflow blueprint, or upload it as a file. '
    . 'Use one or the other, not both.'
);

echo $this->Form->create('WorkflowBlueprint', [
    'class' => 'needs-validation',
    'novalidate' => true,
    'url' => $this->request->here(false),
    'enctype' => 'multipart/form-data',
]);
?>

<?php if ($isModal): ?>
<?= $this->element('genericElementsBS5/Forms/modal_header', [
    'accent' => 'primary',
    'eyebrow' => __('Workflow Blueprints'),
    'title' => __('Import workflow blueprint'),
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

        <!-- ── Workflow Blueprint  ───────────────────────────────── -->
        <div class="w-100 px-2">
            <?= $this->element('genericElementsBS5/Forms/json_field', [
                'field' => 'json',
                'label' => __('Workflow Blueprint JSON'),
                'shape' => 'object',
                'rows' => 14,
                'minHeight' => '280px',
                'placeholder' => "{\n    \"WorkflowBlueprint\": {\n        \"name\": \"…\",\n        \"data\": []\n    }\n}",
                'hint' => __('The export document of a blueprint — leave it empty to upload the file instead.'),
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
                'text' => __('Optional — A blueprint exported from this or another MISP instance.'),
            ]) ?>
        </div>

    </div>

    <?= $this->element('genericElementsBS5/Forms/modal_footer', [
        'hint' => __('If both a pasted document and a file are provided, the file wins.'),
        'cancel' => $isModal ? [] : [
            'label' => __('Cancel'),
            'href' => $baseurl . '/workflowBlueprints/index',
            'attrs' => [],
        ],
        'submit' => ['label' => __('Import'), 'icon' => 'fas fa-upload'],
    ]) ?>
</div>

<?= $this->Form->end() ?>