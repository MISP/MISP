<?php
$edit = $this->request->params['action'] === 'edit' ? true : false;

echo $this->Form->create('Template', [
    'class' => 'needs-validation',
    'novalidate' => true
]);
?>

<div class="container me-5">

    <div class="row justify-content-center">

        <div class="card shadow-sm">

            <div class="card-body">

                <h3 class="mb-2">
                    <?=  $edit ? __('Edit Template') : __('Create New Template')  ?>
                </h3>

                <!-- NAME -->
                <div class="mb-3">
                    <?= $this->Form->label('name', __('Name'), ['class' => 'form-label fw-semibold']) ?>

                    <?= $this->Form->control('name', [
                        'label' => false,
                        'class' => 'form-control bg-light',
                        'placeholder' => 'Template name',
                        'required' => true
                    ]) ?>
                </div>

                <!-- DESCRIPTION -->
                <div class="mb-4">
                    <?= $this->Form->label('description', __('Description') . ' (Optional)', ['class' => 'form-label fw-semibold']) ?>

                    <?= $this->Form->textarea('description', [
                        'class' => 'form-control bg-light',
                        'rows' => 5,
                        'placeholder' => __('A description of the template')
                    ]) ?>
                </div>

                <!-- TAGS -->
                <div class="mb-4">
                    <?= $this->Form->label('tags', __('Tags'), ['class' => 'form-label fw-semibold']) ?>

                    <?= $this->Form->select('tags', $tags ?? [], [
                        'multiple' => true,
                        'class' => 'form-select tom-select bg-light',
                        'data-placeholder' => __('Search and add tags...')
                    ]) ?>
                </div>

                <!-- SHARE -->
                <div class="mb-4">
                    <div class="form-check form-switch">
                        <?= $this->Form->checkbox('share', [
                            'class' => 'form-check-input', 
                            'id' => 'checkShare',
                            'hiddenField' => true,
                            'checked' => (isset($share) && $share === true)
                        ]) ?>
                        <?= $this->Form->label('checkShare', __('Share this template with others'), ['class' => 'form-check-label']) ?>
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
                        '<i class="fas fa-check me-1"></i> ' . ($edit ? __('template') : __('Add new template')), 
                        [
                            'class' => 'btn btn-primary',
                            'escapeTitle' => false,
                            'title' => $edit ? __('Edit template') : __('Add new template'),
                            'aria-label' => $edit ? __('Edit template') : __('Add new template'),
                        ]
                    ) ?>
                </div>

            </div>

        </div>

    </div>

</div>

<?= $this->Form->end(); ?>