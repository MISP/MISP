<?php
$edit = $this->request->params['action'] === 'edit';

echo $this->Form->create('Cerebrate', [
    'class' => 'needs-validation',
    'novalidate' => true
]);
?>

<div class="container me-5">
    <div class="row justify-content-center">
        <div class="card shadow-sm">
            <div class="card-body">

                <h3 class="mb-3">
                    <?= $edit ? __('Edit Cerebrate') : __('Add Cerebrate') ?>
                </h3>

                <!-- NAME -->
                <div class="mb-3">
                    <?= $this->Form->label('name', __('Name'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->control('name', [
                        'label' => false,
                        'class' => 'form-control bg-light',
                        'required' => true
                    ]) ?>
                </div>


                <!-- DESCRIPTION -->
                <div class="mb-3">
                    <?= $this->Form->label('description', __('Description') . (' (Optional)'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->textarea('description', [
                        'class' => 'form-control bg-light',
                        'rows' => 3
                    ]) ?>
                </div>

                <hr class="my-4">

                <!-- OWNER -->
                <div class="mb-3">
                    <?= $this->Form->label('org_id', __('Owner Organisation'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->select('org_id', $dropdownData['org_id'], [
                        'label' => false,
                        'class' => 'form-select tom-select bg-light'
                    ]) ?>
                </div>

                <!-- BASE URL -->
                <div class="mb-3">
                    <?= $this->Form->label('url', __('URL'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->control('url', [
                        'label' => false,
                        'class' => 'form-control bg-light',
                        'placeholder' => 'https://example.com/cerebrate3/'
                    ]) ?>
                </div>

                <!-- API KEY -->
                <div class="mb-3">
                    <?= $this->Form->label('authkey', __('Authentication Key'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->control('authkey', [
                        'label' => false,
                        'class' => 'form-control bg-light'
                    ]) ?>
                </div>

                <!-- OPTIONS -->
                <div class="form-check form-switch mb-4">
                    <?= $this->Form->checkbox('skip_proxy', [
                        'class' => 'form-check-input',
                    ]) ?>
                    <?= $this->Form->label('skip_proxy', __('Skip Proxy (if applicable)'), ['class' => 'form-check-label']) ?>
                </div>

                <div class="form-check form-switch mb-4">
                    <?= $this->Form->checkbox('pull_orgs', [
                        'class' => 'form-check-input',
                    ]) ?>
                    <?= $this->Form->label('pull_orgs', __('Pull Organisations'), ['class' => 'form-check-label']) ?>
                </div>

                <div class="form-check form-switch mb-4">
                    <?= $this->Form->checkbox('pull_sharing_groups', [
                        'class' => 'form-check-input',
                    ]) ?>
                    <?= $this->Form->label('pull_sharing_groups', __('Pull Sharing Groups'), ['class' => 'form-check-label']) ?>
                </div>

                <!-- ACTIONS -->
                <div class="d-flex justify-content-end gap-3">
                    <button type="button" class="btn btn-outline-secondary" onclick="history.back()">
                        <?= __('Cancel') ?>
                    </button>

                    <?= $this->Form->button(
                        '<i class="fas fa-check me-1"></i> ' . ($edit ? __('Edit cerebrate') : __('Add new cerebrate')), 
                        [
                            'class' => 'btn btn-primary',
                            'escapeTitle' => false,
                            'title' => $edit ? __('Edit cerebrate') : __('Add new cerebrate'),
                            'aria-label' => $edit ? __('Edit cerebrate') : __('Add new cerebrate'),
                        ]
                    ) ?>
                </div>
            </div>
        </div>
    </div>
</div>

<?= $this->Form->end(); ?>