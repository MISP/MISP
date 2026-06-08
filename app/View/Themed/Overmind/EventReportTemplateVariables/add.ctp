<?php
$edit = $this->request->params['action'] === 'edit' ? true : false;

echo $this->Form->create('EventReportTemplateVariable', [
    'class' => 'needs-validation',
    'novalidate' => true
]);
?>

<div class="container me-5">

    <div class="row justify-content-center">

        <div class="card shadow-sm">

            <div class="card-body">

                <h3 class="mb-2">
                    <?=  $edit ? __('Edit current variable') : __('Create New Variable')  ?>
                </h3>

                <!-- NAME -->
                <div class="mb-3">
                    <?= $this->Form->label('name', __('Name'), ['class' => 'form-label fw-semibold']) ?>

                    <?= $this->Form->control('name', [
                        'label' => false,
                        'class' => 'form-control bg-light',
                        'placeholder' => 'Will be used as {{ variable_name }} in the template',
                        'required' => true
                    ]) ?>
                </div>

                <!-- VALUE -->
                <div class="mb-4">
                    <?= $this->Form->label('value', __('Value'), ['class' => 'form-label fw-semibold']) ?>

                    <?= $this->Form->textarea('value', [
                        'class' => 'form-control bg-light',
                        'rows' => 10,
                        'placeholder' => __('')
                    ]) ?>
                </div>

                <!-- ACTION -->
                <div class="d-flex justify-content-end gap-3">
                    <button type="button"
                            class="btn btn-outline-secondary"
                            data-bs-dismiss="modal">
                        <?= __('Cancel') ?>
                    </button>
                    <?= $this->Form->button(
                        '<i class="fas fa-check me-1"></i> ' . ($edit ? __('Edit variable') : __('Add new variable')), 
                        [
                            'class' => 'btn btn-primary',
                            'escapeTitle' => false,
                            'title' => $edit ? __('Edit variable') : __('Add new variable'),
                            'aria-label' => $edit ? __('Edit variable') : __('Add new variable'),
                        ]
                    ) ?>
                </div>

            </div>

        </div>

    </div>

</div>

<?= $this->Form->end(); ?>