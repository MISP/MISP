<?php
$modelForForm = 'SharingGroupBlueprints';

echo $this->Form->create('SharingGroupBlueprint', [
    'class' => 'needs-validation',
    'novalidate' => true
]);
?>

<div class="container me-5">

    <div class="row justify-content-center">

        <div class="card shadow-sm">

            <div class="card-body">

                <h3 class="mb-2">
                    <?= __('Create sync rules') ?>
                </h3>

                <p class="text-muted mb-4">
                    <?= __('Create a push/pull organisation filter rule based on the organisations contained in a blueprint. The selected blueprint rules will be transposed as either a push or a pull rule using OR or NOT logic.') ?>
                </p>

                <div class="row g-4">

                    <!-- TYPE -->
                    <div class="col-md-4">
                        <?= $this->Form->label(
                            'type',
                            __('Sync direction'),
                            ['class' => 'form-label fw-semibold']
                        ) ?>

                        <?= $this->Form->select(
                            'type',
                            [
                                'pull' => __('Pull'),
                                'push' => __('Push')
                            ],
                            [
                                'empty' => __('Select a direction...'),
                                'class' => 'form-select tom-select bg-light',
                                'required' => true
                            ]
                        ) ?>

                        <div class="form-text">
                            <?= __('Choose whether the rule applies to pushed or pulled data.') ?>
                        </div>
                    </div>

                    <!-- RULE -->
                    <div class="col-md-4">
                        <?= $this->Form->label(
                            'rule',
                            __('Rule logic'),
                            ['class' => 'form-label fw-semibold']
                        ) ?>

                        <?= $this->Form->select(
                            'rule',
                            [
                                'OR' => 'OR',
                                'NOT' => 'NOT'
                            ],
                            [
                                'empty' => __('Select a rule type...'),
                                'class' => 'form-select tom-select bg-light',
                                'required' => true
                            ]
                        ) ?>

                        <div class="form-text">
                            <?= __('OR will include matching organisations, NOT will exclude them.') ?>
                        </div>
                    </div>

                    <!-- SERVER -->
                    <div class="col-md-4">
                        <?= $this->Form->label(
                            'server_id',
                            __('Target server'),
                            ['class' => 'form-label fw-semibold']
                        ) ?>

                        <?= $this->Form->select(
                            'server_id',
                            $servers ?? [],
                            [
                                'empty' => __('Select a server...'),
                                'class' => 'form-select tom-select bg-light',
                                'required' => true
                            ]
                        ) ?>

                        <div class="form-text">
                            <?= __('Select the remote server on which the sync rule will be applied.') ?>
                        </div>
                    </div>

                </div>

                <!-- ACTIONS -->
                <div class="d-flex justify-content-end gap-3 mt-5">

                    <button
                        type="button"
                        class="btn btn-outline-secondary"
                        data-bs-dismiss="modal"
                    >
                        <?= __('Cancel') ?>
                    </button>

                    <?= $this->Form->button(
                        '<i class="fas fa-check me-1"></i> ' . __('Create sync rules'),
                        [
                            'class' => 'btn btn-primary',
                            'escapeTitle' => false,
                            'title' => __('Create sync rules'),
                            'aria-label' => __('Create sync rules')
                        ]
                    ) ?>

                </div>

            </div>

        </div>

    </div>

</div>

<?= $this->Form->end(); ?>