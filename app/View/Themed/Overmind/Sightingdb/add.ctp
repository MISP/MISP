<?php
$edit = $this->request->params['action'] === 'edit';

echo $this->Form->create('Sightingdb', [
    'class' => 'needs-validation',
    'novalidate' => true
]);
?>

<div class="container me-5">
    <div class="row justify-content-center">

        <div class="card shadow-sm">
            <div class="card-body">

                <h3 class="mb-3">
                    <?= $edit ? __('Edit SightingDB connection') : __('Add SightingDB connection') ?>
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
                    <?= $this->Form->label('description', __('Description') . ' (Optional)', ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->textarea('description', [
                        'class' => 'form-control bg-light',
                        'rows' => 3
                    ]) ?>
                </div>

                <hr class="my-4">

                <!-- HOST -->
                <div class="mb-3">
                    <?= $this->Form->label('host', __('Host'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->control('host', [
                        'label' => false,
                        'class' => 'form-control bg-light'
                    ]) ?>
                </div>

                <!-- PORT -->
                <div class="mb-3">
                    <?= $this->Form->label('port', __('Port'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->control('port', [
                        'label' => false,
                        'class' => 'form-control bg-light'
                    ]) ?>
                </div>

                <hr class="my-4">

                <!-- NAMESPACE -->
                <div class="mb-3">
                    <?= $this->Form->label('namespace', __('Namespace'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->control('namespace', [
                        'label' => false,
                        'class' => 'form-control bg-light'
                    ]) ?>
                </div>

                <!-- OWNER -->
                <div class="mb-3">
                    <?= $this->Form->label('owner', __('Owner'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->control('owner', [
                        'label' => false,
                        'class' => 'form-control bg-light'
                    ]) ?>
                </div>

                <hr class="my-4">

                <!-- ORG RESTRICTIONS -->
                <div class="mb-4">
                    <?= $this->Form->label('org_id', __('Organisation restrictions'), ['class' => 'form-label fw-semibold']) ?>

                    <?= $this->Form->select('org_id', $orgs ?? [], [
                        'multiple' => true,
                        'class' => 'form-select tom-select bg-light',
                        'data-placeholder' => __('Select organisations...')
                    ]) ?>

                    <div class="form-text">
                        <?= __('Leave empty for unrestricted access.') ?>
                    </div>
                </div>

                <!-- SWITCHES -->
                <div class="form-check form-switch mb-2">
                    <?= $this->Form->checkbox('enabled', ['class' => 'form-check-input']) ?>
                    <label class="form-check-label"><?= __('Enabled') ?></label>
                </div>

                <div class="form-check form-switch mb-2">
                    <?= $this->Form->checkbox('skip_proxy', ['class' => 'form-check-input']) ?>
                    <label class="form-check-label"><?= __('Skip proxy') ?></label>
                </div>

                <div class="form-check form-switch mb-4">
                    <?= $this->Form->checkbox('ssl_skip_verification', ['class' => 'form-check-input']) ?>
                    <label class="form-check-label"><?= __('Skip SSL verification') ?></label>
                </div>

                <!-- ACTION -->
                <div class="d-flex justify-content-end gap-3">
                    <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">
                        <?= __('Cancel') ?>
                    </button>

                    <?= $this->Form->button(
                        '<i class="fas fa-check me-1"></i> ' . ($edit ? __('Edit sightingdb') : __('Add sightingdb')), 
                        [
                            'class' => 'btn btn-primary',
                            'escapeTitle' => false,
                            'title' => $edit ? __('Edit sightingdb') : __('Add sightingdb'),
                            'aria-label' => $edit ? __('Edit sightingdb') : __('Add sightingdb'),
                        ]
                    ) ?>
                </div>

            </div>
        </div>

    </div>
</div>

<?= $this->Form->end(); ?>