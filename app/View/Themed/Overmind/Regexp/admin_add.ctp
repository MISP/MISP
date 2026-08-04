<?php
$edit = $this->request->params['action'] === 'admin_edit' ? true : false;

echo $this->Form->create('Regexp', [
    'class' => 'needs-validation',
    'novalidate' => true
]);

?>

<div class="container me-5">

    <div class="row justify-content-center">

        <div class="card shadow-sm">

            <div class="card-body">

                <h3 class="mb-2">
                    <?=  $edit ? __('Edit current regexp') : __('Create New Regexp')  ?>
                </h3>

                <!-- NAME -->
                <div class="mb-3">
                    <?= $this->Form->label('regexp', __('Regexp'), ['class' => 'form-label fw-semibold']) ?>

                    <?= $this->Form->control('regexp', [
                        'label' => false,
                        'class' => 'form-control bg-light',
                        'placeholder' => '',
                        'required' => true
                    ]) ?>
                </div>

                <!-- REPLACEMENT -->
                <div class="mb-3">
                    <?= $this->Form->label('replacement', __('Replacement'), ['class' => 'form-label fw-semibold']) ?>

                    <?= $this->Form->control('replacement', [
                        'label' => false,
                        'class' => 'form-control bg-light',
                        'placeholder' => '',
                        'required' => false
                    ]) ?>
                </div>

                <!-- TYPE -->
                <div class="mb-4">
                    <?= $this->Form->label('type', __('Affected Types'), ['class' => 'form-label fw-semibold']) ?>

                    <div class="mb-2" id="specificTypesContainer">
                        <?= $this->Form->select('selected_types', $types, [
                            'multiple' => true,
                            'class' => 'form-select tom-select bg-light',
                            'data-placeholder' => __('Select one or more types...')
                        ]) ?>
                    </div>

                    <div class="form-check form-switch">
                        <?= $this->Form->checkbox('all', [
                            'class' => 'form-check-input', 
                            'id' => 'checkAllTypes',
                            'hiddenField' => true,
                            'checked' => (isset($all) && $all === true)
                        ]) ?>
                        <?= $this->Form->label('checkAllTypes', __('Apply to ALL types'), ['class' => 'form-check-label']) ?>
                    </div>

                    <div class="form-text">
                        <?= __("Setting 'all' will override specific type selections.") ?>
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
                        '<i class="fas fa-check me-1"></i> ' . ($edit ? __('Edit regexp') : __('Add new regexp')), 
                        [
                            'class' => 'btn btn-primary',
                            'escapeTitle' => false,
                            'title' => $edit ? __('Edit regexp') : __('Add new regexp'),
                            'aria-label' => $edit ? __('Edit regexp') : __('Add new regexp'),
                        ]
                    ) ?>
                </div>

            </div>

        </div>

    </div>

</div>

<?= $this->Form->end(); ?>