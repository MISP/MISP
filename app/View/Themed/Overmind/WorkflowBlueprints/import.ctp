<?php
echo $this->Form->create('WorkflowBlueprint', [
    'class' => 'needs-validation',
    'novalidate' => true,
    'url' => $this->request->here(false),
    'enctype' => 'multipart/form-data',
]);
?>

<div class="container me-5">
    <div class="row justify-content-center">
        <div class="card shadow-sm">
            <div class="card-body">

                <h3 class="mb-2"><?= __('Import workflow blueprint') ?></h3>

                <div class="form-text mb-3">
                    <?= __('Paste the JSON of a workflow blueprint, or upload it as a file. Use one or the other, not both.') ?>
                </div>

                <!-- PASTED JSON -->
                <div class="mb-3">
                    <?= $this->Form->label('json', __('JSON'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->textarea('json', [
                        'class' => 'form-control font-monospace',
                        'rows' => 12,
                        'placeholder' => __('Workflow blueprint JSON'),
                    ]) ?>
                </div>

                <!-- OR A FILE -->
                <div class="mb-4">
                    <?= $this->Form->label('submittedjson', __('JSON file'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->file('submittedjson', ['class' => 'form-control']) ?>
                    <div class="form-text">
                        <?= __('A blueprint exported from this or another MISP instance.') ?>
                    </div>
                </div>

                <!-- ACTIONS -->
                <div class="d-flex justify-content-end gap-3">
                    <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">
                        <?= __('Cancel') ?>
                    </button>
                    <?= $this->Form->button(
                        '<i class="fas fa-file-import me-1"></i> ' . __('Import'),
                        [
                            'class' => 'btn btn-primary',
                            'escapeTitle' => false,
                            'title' => __('Import'),
                            'aria-label' => __('Import'),
                        ]
                    ) ?>
                </div>

            </div>
        </div>
    </div>
</div>

<?= $this->Form->end(); ?>
