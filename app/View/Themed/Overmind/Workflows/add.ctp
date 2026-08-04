<?php
/*
 * `data` is deliberately a hidden passthrough rather than an editable field:
 *   - on add it stays empty, which is what makes addWorkflow() generate an
 *     ad-hoc trigger and its starting graph;
 *   - on edit it must be posted back untouched, because edit() JSON-decodes
 *     whatever arrives and copies it over the saved workflow — dropping the
 *     field would wipe the graph.
 * The graph is built in the editor, never here.
 */
$edit = $this->request->params['action'] === 'edit';

echo $this->Form->create('Workflow', [
    'class' => 'needs-validation',
    'novalidate' => true,
    'url' => $edit
        ? ['action' => 'edit', $this->request->params['pass'][0]]
        : ['action' => 'add'],
]);
?>

<div class="container me-5">
    <div class="row justify-content-center">
        <div class="card shadow-sm">
            <div class="card-body">

                <h3 class="mb-2">
                    <?= $edit ? __('Edit workflow') : __('Add ad-hoc workflow') ?>
                </h3>

                <div class="form-text mb-3">
                    <?= $edit
                        ? __('Name, description and debug mode. The graph itself is edited in the workflow editor.')
                        : __('Creates a workflow with its own ad-hoc trigger, to be run manually. Open it in the editor afterwards to build the graph and choose which data the trigger feeds in.') ?>
                </div>

                <!-- NAME -->
                <div class="mb-3">
                    <?= $this->Form->label('name', __('Name'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->text('name', [
                        'class' => 'form-control',
                        'required' => true,
                        'placeholder' => __('Name of the workflow'),
                    ]) ?>
                </div>

                <!-- DESCRIPTION -->
                <div class="mb-3">
                    <?= $this->Form->label('description', __('Description'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->textarea('description', [
                        'class' => 'form-control',
                        'rows' => 3,
                        'placeholder' => __('What this workflow does'),
                    ]) ?>
                </div>

                <?php if ($edit): ?>
                    <!-- DEBUG MODE -->
                    <div class="form-check mb-4">
                        <?= $this->Form->checkbox('debug_enabled', ['class' => 'form-check-input', 'id' => 'WorkflowDebugEnabled']) ?>
                        <label class="form-check-label" for="WorkflowDebugEnabled">
                            <?= __('Debug mode') ?>
                        </label>
                        <div class="form-text">
                            <?= __('Every node sends its data to Plugin.Workflow_debug_url.') ?>
                        </div>
                    </div>
                <?php endif; ?>

                <?= $this->Form->hidden('data') ?>

                <!-- ACTIONS -->
                <div class="d-flex justify-content-end gap-3">
                    <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">
                        <?= __('Cancel') ?>
                    </button>
                    <?= $this->Form->button(
                        '<i class="fas fa-check me-1"></i> ' . ($edit ? __('Save changes') : __('Add workflow')),
                        [
                            'class' => 'btn btn-primary',
                            'escapeTitle' => false,
                            'title' => $edit ? __('Save changes') : __('Add workflow'),
                            'aria-label' => $edit ? __('Save changes') : __('Add workflow'),
                        ]
                    ) ?>
                </div>

            </div>
        </div>
    </div>
</div>

<?= $this->Form->end(); ?>
