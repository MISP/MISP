<?php
$edit = $this->request->params['action'] === 'edit' ? true : false;

echo $this->Form->create('Bookmark', [
    'class' => 'needs-validation',
    'novalidate' => true
]);
?>

<div class="container me-5">

    <div class="row justify-content-center">

        <div class="card shadow-sm">

            <div class="card-body">

                <h3 class="mb-2">
                    <?= $edit ? __('Edit bookmark') : __('Add bookmark') ?>
                </h3>

                <div class="form-text mb-3">
                    <?= __('Bookmarks are added to the navigation top bar. Each bookmark can optionally be exposed to all users belonging to your organisation.') ?>
                </div>

                <!-- NAME -->
                <div class="mb-3">
                    <?= $this->Form->label('name', __('Name'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->text('name', ['class' => 'form-control', 'required' => true, 'placeholder' => __('Name of the bookmark')]) ?>
                </div>

                <!-- URL -->
                <div class="mb-3">
                    <?= $this->Form->label('url', __('URL'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->textarea('url', ['class' => 'form-control', 'rows' => 2, 'required' => true]) ?>
                </div>

                <!-- COMMENT -->
                <div class="mb-3">
                    <?= $this->Form->label('comment', __('Comment'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->textarea('comment', ['class' => 'form-control', 'rows' => 3]) ?>
                </div>

                <!-- EXPOSED TO ORG -->
                <div class="mb-4 form-check">
                    <?= $this->Form->checkbox('exposed_to_org', ['class' => 'form-check-input', 'id' => 'BookmarkExposedToOrg']) ?>
                    <?= $this->Form->label('exposed_to_org', __('Expose to all users from the organisation'), ['class' => 'form-check-label', 'for' => 'BookmarkExposedToOrg']) ?>
                </div>

                <!-- ACTIONS -->
                <div class="d-flex justify-content-end gap-3">
                    <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">
                        <?= __('Cancel') ?>
                    </button>
                    <?= $this->Form->button(
                        '<i class="fas fa-check me-1"></i> ' . ($edit ? __('Save changes') : __('Add bookmark')),
                        [
                            'class' => 'btn btn-primary',
                            'escapeTitle' => false,
                            'title' => $edit ? __('Save changes') : __('Add bookmark'),
                            'aria-label' => $edit ? __('Save changes') : __('Add bookmark'),
                        ]
                    ) ?>
                </div>

            </div>

        </div>

    </div>

</div>

<?= $this->Form->end(); ?>
