<?php
$edit = $this->request->params['action'] === 'edit' ? true : false;

echo $this->Form->create('WorkflowBlueprint', [
    'class' => 'needs-validation',
    'novalidate' => true
]);
?>

<div class="container me-5">

    <div class="row justify-content-center">

        <div class="card shadow-sm">

            <div class="card-body">

                <h3 class="mb-2">
                    <?= $edit ? __('Edit workflow blueprint') : __('Add workflow blueprint') ?>
                </h3>

                <?php
                /*
                 * Surface field errors up front — an import lands here
                 * with the offending values already filled in.
                 */
                $errors = $this->validationErrors['WorkflowBlueprint'] ?? [];
                ?>
                <?php if (!empty($errors)): ?>
                    <div class="alert alert-danger py-2" role="alert">
                        <div class="fw-semibold mb-1">
                            <i class="fas fa-circle-exclamation me-1"></i><?= __('The blueprint could not be saved.') ?>
                        </div>
                        <ul class="mb-0 small">
                            <?php foreach ($errors as $errField => $messages): ?>
                                <?php foreach ((array)$messages as $message): ?>
                                    <li><strong><?= h($errField) ?></strong>: <?= h($message) ?></li>
                                <?php endforeach; ?>
                            <?php endforeach; ?>
                        </ul>
                    </div>
                <?php endif; ?>

                <div class="form-text mb-3">
                    <?= __('Workflow blueprints are re-usable blocks of workflow logic. The data field holds the blueprint graph as JSON; it is normally produced by the workflow editor.') ?>
                </div>

                <!-- NAME -->
                <div class="mb-3">
                    <?= $this->Form->label('name', __('Name'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->text('name', ['class' => 'form-control', 'required' => true, 'placeholder' => __('Name of the workflow blueprint')]) ?>
                </div>

                <!-- DESCRIPTION -->
                <div class="mb-3">
                    <?= $this->Form->label('description', __('Description'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->textarea('description', ['class' => 'form-control', 'rows' => 3, 'placeholder' => __('Concise description of the workflow blueprint')]) ?>
                </div>

                <!-- DATA -->
                <div class="mb-4">
                    <?= $this->Form->label('data', __('Data (JSON)'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->textarea('data', [
                        'class' => 'form-control font-monospace',
                        'rows' => 10,
                        'placeholder' => '[]'
                    ]) ?>
                    <div class="form-text"><?= __('The blueprint graph as a JSON array of blocks.') ?></div>
                </div>

                <!-- ACTIONS -->
                <div class="d-flex justify-content-end gap-3">
                    <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">
                        <?= __('Cancel') ?>
                    </button>
                    <?= $this->Form->button(
                        '<i class="fas fa-check me-1"></i> ' . ($edit ? __('Save changes') : __('Add blueprint')),
                        [
                            'class' => 'btn btn-primary',
                            'escapeTitle' => false,
                            'title' => $edit ? __('Save changes') : __('Add blueprint'),
                            'aria-label' => $edit ? __('Save changes') : __('Add blueprint'),
                        ]
                    ) ?>
                </div>

            </div>

        </div>

    </div>

</div>

<?= $this->Form->end(); ?>
