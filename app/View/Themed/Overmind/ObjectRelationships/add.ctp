<?php
$edit = $this->request->params['action'] === 'edit' ? true : false;

echo $this->Form->create('ObjectRelationship', [
    'class' => 'needs-validation',
    'novalidate' => true
]);
?>

<div class="container me-5">

    <div class="row justify-content-center">

        <div class="card shadow-sm">

            <div class="card-body">

                <h3 class="mb-2">
                    <?=  $edit ? __('Edit ObjectRelationship') : __('Create New ObjectRelationship')  ?>
                </h3>

                <!-- NAME -->
                <div class="mb-3">
                    <?= $this->Form->label('name', __('Name'), ['class' => 'form-label fw-semibold']) ?>

                    <?= $this->Form->control('name', [
                        'label' => false,
                        'class' => 'form-control bg-light',
                        'placeholder' => 'Relationship name',
                        'required' => true
                    ]) ?>
                </div>

                <!-- DESCRIPTION -->
                <div class="mb-4">
                    <?= $this->Form->label('description', __('Description') . ' (Optional)', ['class' => 'form-label fw-semibold']) ?>

                    <?= $this->Form->textarea('description', [
                        'class' => 'form-control bg-light',
                        'rows' => 5,
                        'placeholder' => __('A description of the relationship')
                    ]) ?>
                </div>

                <!-- HIGHLIGHTED -->
                <div class="mb-4">
                    <div class="form-check form-switch">
                        <?= $this->Form->checkbox('highlighted', [
                            'class' => 'form-check-input', 
                            'id' => 'checkHighlighted',
                            'hiddenField' => true,
                            'checked' => (isset($highlighted) && $highlighted === true)
                        ]) ?>
                        <?= $this->Form->label('checkHighlighted', __('Highlight this relationship'), ['class' => 'form-check-label']) ?>
                    </div>
                </div>


                <!-- ACTION -->
                <div class="d-flex justify-content-end gap-3">
                    <button type="button"
                            class="btn btn-outline-secondary"
                            data-bs-dismiss="modal">
                        <?= __('Cancel') ?>
                    </button>
                    <?= $this->Form->button(
                        '<i class="fas fa-check me-1"></i> ' . ($edit ? __('Edit relationship') : __('Add new relationship')), 
                        [
                            'class' => 'btn btn-primary',
                            'escapeTitle' => false,
                            'title' => $edit ? __('Edit relationship') : __('Add new relationship'),
                            'aria-label' => $edit ? __('Edit relationship') : __('Add new relationship'),
                        ]
                    ) ?>
                </div>

            </div>

        </div>

    </div>

</div>

<?= $this->Form->end(); ?>