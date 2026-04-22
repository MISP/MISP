<?php
$edit = $this->request->params['action'] === 'edit';

echo $this->Form->create('Tag', [
    'class' => 'needs-validation',
    'novalidate' => true
]);

?>

<div class="container me-5">
    <div class="row justify-content-center">
        <div class="card shadow-sm">
            <div class="card-body">

                <h3 class="mb-3">
                    <?= $edit ? __('Edit Tag') : __('Create New Tag') ?>
                </h3>

                <!-- NAME -->
                <div class="mb-3">
                    <?= $this->Form->label('name', __('Name'), ['class' => 'form-label fw-semibold']) ?>

                    <?= $this->Form->control('name', [
                        'label' => false,
                        'class' => 'form-control bg-light',
                        'placeholder' => __('e.g. tlp:red or malware:apt'),
                        'required' => true
                    ]) ?>
                </div>

                <!-- COLOR -->
                <div class="mb-3">
                    <?= $this->Form->label('colour', __('Colour'), ['class' => 'form-label fw-semibold']) ?>

                    <div class="d-flex align-items-center gap-3">
                        <?= $this->Form->control('colour', [
                            'label' => false,
                            'type' => 'color',
                            'class' => 'form-control form-control-color',
                            'style' => 'width: 60px; height: 40px;'
                        ]) ?>

                        <span class="form-text">
                            <?= __('Choose a color for the tag display') ?>
                        </span>
                    </div>
                </div>

                <!-- ORG -->
                <div class="mb-3">
                    <?= $this->Form->label('org_id', __('Restrict to organisation'), ['class' => 'form-label fw-semibold']) ?>

                    <?= $this->Form->select('org_id', $orgs ?? [], [
                        'empty' => __('No restriction'),
                        'value' => $edit ? null : 0,
                        'class' => 'form-select tom-select bg-light'
                    ]) ?>
                </div>

                <!-- USER -->
                <?php if ($isSiteAdmin): ?>
                    <div class="mb-3">
                        <?= $this->Form->label('user_id', __('Restrict to user'), ['class' => 'form-label fw-semibold']) ?>

                        <?= $this->Form->select('user_id', $users ?? [], [
                            'empty' => __('No restriction'),
                            'value' => $edit ? null : 0,
                            'class' => 'form-select tom-select bg-light'
                        ]) ?>
                    </div>
                <?php endif; ?>

                <!-- OPTIONS -->
                <div class="mb-4">
                    <label class="form-label fw-semibold"><?= __('Options') ?></label>

                    <div class="form-check">
                        <?= $this->Form->checkbox('exportable', [
                            'class' => 'form-check-input',
                            'checked' => true
                        ]) ?>
                        <?= $this->Form->label('exportable', __('Exportable'), ['class' => 'form-check-label']) ?>
                    </div>

                    <div class="form-check">
                        <?= $this->Form->checkbox('hide_tag', [
                            'class' => 'form-check-input'
                        ]) ?>
                        <?= $this->Form->label('hide_tag', __('Hide this tag'), ['class' => 'form-check-label']) ?>
                    </div>

                    <div class="form-check">
                        <?= $this->Form->checkbox('local_only', [
                            'class' => 'form-check-input'
                        ]) ?>
                        <?= $this->Form->label('local_only', __('Local only (not shared)'), ['class' => 'form-check-label']) ?>
                    </div>
                </div>

                <!-- ACTIONS -->
                <div class="d-flex justify-content-end gap-3">
                    <button type="button"
                            class="btn btn-outline-secondary"
                            data-bs-dismiss="modal">
                        <?= __('Cancel') ?>
                    </button>

                    <?= $this->Form->button(
                        '<i class="fas fa-check me-1"></i> ' . ($edit ? __('Save changes') : __('Create tag')),
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