<?php
$edit = $this->request->params['action'] === 'editWithTags';

echo $this->Form->create('TagCollection', [
    'class' => 'needs-validation',
    'novalidate' => true
]);
?>

<div class="container me-5">
    <div class="row justify-content-center">

        <div class="card shadow-sm">
            <div class="card-body">

                <h3 class="mb-3">
                    <?= $edit ? __('Edit Tag Collection') : __('Create Tag Collection') ?>
                </h3>

                <!-- NAME -->
                <div class="mb-3">
                    <?= $this->Form->label('name', __('Name'), ['class' => 'form-label fw-semibold']) ?>

                    <?= $this->Form->control('name', [
                        'label' => false,
                        'class' => 'form-control bg-light',
                        'placeholder' => __('Collection name...'),
                        'required' => true
                    ]) ?>
                </div>

                <!-- DESCRIPTION -->
                <div class="mb-3">
                    <?= $this->Form->label('description', __('Description'), ['class' => 'form-label fw-semibold']) ?>

                    <?= $this->Form->textarea('description', [
                        'class' => 'form-control bg-light',
                        'rows' => 2,
                        'placeholder' => __('Optional description...')
                    ]) ?>
                </div>

                <!-- VISIBILITY -->
                <div class="form-check form-switch mb-4">
                    <?= $this->Form->checkbox('all_orgs', [
                        'class' => 'form-check-input',
                        'id' => 'all_orgs'
                    ]) ?>
                    <label class="form-check-label" for="all_orgs">
                        <?= __('Visible to all organisations') ?>
                    </label>
                </div>

                <!-- TAGS -->
                <div class="mb-4">
                    <?= $this->Form->label('tags', __('Tags'), ['class' => 'form-label fw-semibold']) ?>

                    <?= $this->Form->select('tags', $allTags ?? [], [
                        'multiple' => true,
                        'class' => 'form-select tom-select bg-light',
                        'data-placeholder' => __('Search and add tags...')
                    ]) ?>

                    <div class="form-text">
                        <?= __('Search, add or remove tags from this collection.') ?>
                    </div>
                </div>

                <!-- ACTIONS -->
                <div class="d-flex justify-content-end gap-3">
                    <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">
                        <?= __('Cancel') ?>
                    </button>

                    <?= $this->Form->button(
                        '<i class="fas fa-check me-1"></i> ' . ($edit ? __('Save changes') : __('Add new collection')),
                        [
                            'class' => 'btn btn-primary',
                            'escapeTitle' => false
                        ]
                    ) ?>
                </div>

            </div>
        </div>

    </div>
</div>

<?= $this->Form->end(); ?>