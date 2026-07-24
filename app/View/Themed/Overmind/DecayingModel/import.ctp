<?php
echo $this->Form->create('DecayingModel', [
    'enctype' => 'multipart/form-data',
    'class' => 'needs-validation',
    'novalidate' => true,
]);
?>

<div class="container-fluid px-0">
    <div class="card border-0">
        <div class="card-body">

            <h3 class="mb-1"><?= __('Import decaying model') ?></h3>
            <div class="form-text mb-3">
                <?= __('Paste a MISP decaying-model JSON below, or provide a JSON file. The imported model is added to your organisation as a non-default model.') ?>
            </div>

            <div class="mb-3">
                <?= $this->Form->label('json', __('Model JSON'), ['class' => 'form-label fw-semibold']) ?>
                <?= $this->Form->textarea('json', [
                    'class' => 'form-control font-monospace',
                    'rows' => 12,
                    'placeholder' => '{ "name": "...", "formula": "Polynomial", "parameters": { ... } }',
                ]) ?>
            </div>

            <div class="mb-2">
                <?= $this->Form->label('submittedjson', __('… or upload a JSON file'), ['class' => 'form-label fw-semibold']) ?>
                <?= $this->Form->file('submittedjson', ['class' => 'form-control']) ?>
            </div>

            <div class="d-flex justify-content-end gap-3 mt-4">
                <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">
                    <?= __('Cancel') ?>
                </button>
                <?= $this->Form->button(
                    '<i class="fas fa-file-import me-1"></i> ' . __('Import'),
                    ['class' => 'btn btn-primary', 'escapeTitle' => false]
                ) ?>
            </div>

        </div>
    </div>
</div>

<?= $this->Form->end(); ?>
