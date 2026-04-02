<?php
$edit = $this->request->params['action'] === 'edit' ? true : false;

echo $this->Form->create('Warninglist', [
    'class' => 'needs-validation',
    'novalidate' => true
]);
?>

<div class="container me-5">

    <div class="row justify-content-center">

        <div class="card shadow-sm">

            <div class="card-body">

                <h3 class="mb-2">
                    <?=  $edit ? __('Edit current warninglist') : __('Create New Warninglist')  ?>
                </h3>

                <!-- NAME -->
                <div class="mb-3">
                    <?= $this->Form->label('name', __('Name'), ['class' => 'form-label fw-semibold']) ?>

                    <?= $this->Form->control('name', [
                        'label' => false,
                        'class' => 'form-control bg-light',
                        'placeholder' => 'List of known IP address for...',
                        'maxlength' => 60,
                        'required' => true
                    ]) ?>

                    <div class="form-text">
                        <?= __('Keep it short but descriptive. Max 60 characters.') ?>
                    </div>
                </div>

                <!-- DESCRIPTION -->
                <div class="mb-4">
                    <?= $this->Form->label('description', __('Description') . ' (Optional)', ['class' => 'form-label fw-semibold']) ?>

                    <?= $this->Form->textarea('description', [
                        'class' => 'form-control bg-light',
                        'rows' => 2,
                        'placeholder' => __('Briefly describe what this warninglist is for and what it contains...')
                    ]) ?>
                </div>

                <!-- CATEGORY -->
                <div class="mb-3">
                    <?= $this->Form->label('category', __('Category'), ['class' => 'form-label fw-semibold']) ?>

                    <?= $this->Form->select('category', $possibleCategories ?? [], [
                        'empty' => __('Select a category...'),
                        'class' => 'form-select tom-select bg-light'
                    ]) ?>
                </div>

                <!-- TYPE -->
                <div class="mb-3">
                    <?= $this->Form->label('type', __('Type'), ['class' => 'form-label fw-semibold']) ?>

                    <?= $this->Form->select('type', $possibleTypes ?? [], [
                        'empty' => __('Select a type...'),
                        'class' => 'form-select tom-select bg-light'
                    ]) ?>
                </div>

                <!-- ACCEPTED ATTRIBUTE TYPES -->
                <div class="mb-3">
                    <?= $this->Form->label('matching_attributes', __('Accepted attribute types'), ['class' => 'form-label fw-semibold']) ?>

                    <?= $this->Form->select('matching_attributes', $matchingAttributes ?? [], [
                        'multiple' => true,
                        'class' => 'form-select tom-select bg-light',
                        'data-placeholder' => __('Select some options...'),
                    ]) ?>
                </div>

                <!-- VALUES -->
                <div class="mb-4">
                    <?= $this->Form->label('entries', __('Values'), ['class' => 'form-label fw-semibold']) ?>

                    <?= $this->Form->textarea('entries', [
                        'class' => 'form-control bg-light',
                        'rows' => 8,
                        'placeholder' => __('One value per line, for value comment use #')
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
                        '<i class="fas fa-check me-1"></i> ' . ($edit ? __('Edit warninglist') : __('Add new warninglist')), 
                        [
                            'class' => 'btn btn-primary',
                            'escapeTitle' => false,
                            'title' => $edit ? __('Edit warninglist') : __('Add new warninglist'),
                            'aria-label' => $edit ? __('Edit warninglist') : __('Add new warninglist'),
                        ]
                    ) ?>
                </div>

            </div>

        </div>

    </div>

</div>

<?= $this->Form->end(); ?>