<?php
$edit = $this->request->params['action'] === 'edit' ? true : false;

echo $this->Form->create('CollectionElement', [
    'class' => 'needs-validation',
    'novalidate' => true
]);
?>

<div class="container">

    <div class="row justify-content-center">

        <div class="card shadow-sm">

            <div class="card-body">

                <h3 class="mb-4">
                    <?= __('Add element to Collection') ?>
                </h3>

                <!-- UUID -->
                <div class="mb-3">
                    <?= $this->Form->label('name', __('Element Uuid'), ['class' => 'form-label fw-semibold']) ?>

                    <?= $this->Form->control('name', [
                        'label' => false,
                        'name'=> 'data[CollectionElement][element_uuid]',
                        'class' => 'form-control bg-light',
                        'placeholder' => 'e.g., 550e8400-e29b-41d4-a716-446655440000',
                        'maxlength' => 36,
                        'required' => true
                    ]) ?>
                </div>

                <!-- TYPE -->
                <div class="mb-3">
                    <?= $this->Form->label('type', __('Element Type'), ['class' => 'form-label fw-semibold']) ?>

                    <?= $this->Form->select('type', $dropdownData['types'] ?? [], [
                        'empty' => __('Select a type...'),
                        'class' => 'form-select tom-select bg-light'
                    ]) ?>
                </div>

                <!-- DESCRIPTION -->
                <div class="mb-4">
                    <?= $this->Form->label('description', __('Description') . ' (Optional)', ['class' => 'form-label fw-semibold']) ?>

                    <?= $this->Form->textarea('description', [
                        'class' => 'form-control bg-light',
                        'rows' => 4,
                        'placeholder' => __('Briefly describe why this element belongs to the collection')
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
                        '<i class="fas fa-check me-1"></i> ' . ($edit ? __('Edit element') : __('Add element')), 
                        [
                            'class' => 'btn btn-primary',
                            'escapeTitle' => false,
                            'title' => $edit ? __('Edit element') : __('Add element'),
                            'aria-label' => $edit ? __('Edit element') : __('Add element'),
                        ]
                    ) ?>
                </div>

            </div>

        </div>

    </div>

</div>

<?= $this->Form->end(); ?>