<?php
$edit = $this->request->params['action'] === 'edit' ? true : false;

// The selector_list is stored as a JSON array; present it as pretty JSON in the textarea.
if (!empty($this->request->data['CorrelationRule']['selector_list']) && is_array($this->request->data['CorrelationRule']['selector_list'])) {
    $this->request->data['CorrelationRule']['selector_list'] = json_encode($this->request->data['CorrelationRule']['selector_list'], JSON_PRETTY_PRINT);
}

echo $this->Form->create('CorrelationRule', [
    'class' => 'needs-validation',
    'novalidate' => true
]);
?>

<div class="container me-5">

    <div class="row justify-content-center">

        <div class="card shadow-sm">

            <div class="card-body">

                <h3 class="mb-2">
                    <?= $edit ? __('Edit correlation rule') : __('Create new correlation rule') ?>
                </h3>

                <div class="form-text mb-3">
                    <?= __('Create correlation rules to block the creation of correlations between events matching certain criteria. Handy when, for example, a feed\'s daily ingestion causes heavy over-correlation.') ?>
                </div>

                <!-- NAME -->
                <div class="mb-3">
                    <?= $this->Form->label('name', __('Name'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->text('name', ['class' => 'form-control', 'required' => true]) ?>
                </div>

                <!-- COMMENT -->
                <div class="mb-3">
                    <?= $this->Form->label('comment', __('Comment'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->textarea('comment', ['class' => 'form-control', 'rows' => 3]) ?>
                </div>

                <!-- SELECTOR TYPE -->
                <div class="mb-3">
                    <?= $this->Form->label('selector_type', __('Selector type'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->select('selector_type', $dropdownData['selector_types'], ['class' => 'form-select', 'empty' => false]) ?>
                </div>

                <!-- SELECTOR LIST -->
                <div class="mb-4">
                    <?= $this->Form->label('selector_list', __('Selector list (JSON array)'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->textarea('selector_list', [
                        'class' => 'form-control font-monospace',
                        'rows' => 8,
                        'placeholder' => '["value1", "value2"]'
                    ]) ?>
                    <div class="form-text"><?= __('A JSON array of values to match against the selected type.') ?></div>
                </div>

                <!-- ACTIONS -->
                <div class="d-flex justify-content-end gap-3">
                    <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">
                        <?= __('Cancel') ?>
                    </button>
                    <?= $this->Form->button(
                        '<i class="fas fa-check me-1"></i> ' . ($edit ? __('Save changes') : __('Add rule')),
                        [
                            'class' => 'btn btn-primary',
                            'escapeTitle' => false,
                            'title' => $edit ? __('Save changes') : __('Add rule'),
                            'aria-label' => $edit ? __('Save changes') : __('Add rule'),
                        ]
                    ) ?>
                </div>

            </div>

        </div>

    </div>

</div>

<?= $this->Form->end(); ?>
