<?php
$edit = $this->request->params['action'] === 'edit' ? true : false;

echo $this->Form->create('CorrelationExclusion', [
    'class' => 'needs-validation',
    'novalidate' => true
]);

?>

<div class="container me-5">

    <div class="row justify-content-center">

        <div class="card shadow-sm">

            <div class="card-body">

                <h3 class="mb-2">
                    <?=  $edit ? __('Edit current exclusion') : __('Create New Exclusion')  ?>
                </h3>

                <div class="form-text mb-2">
                        <?= __('If you wish to exclude certain entries from being correlated on, simply add an entry here.')?>
                </div>


                <!-- VALUES -->
                <div class="mb-4">
                    <?= $this->Form->label('value', __('Value'), ['class' => 'form-label fw-semibold']) ?>

                    <?= $this->Form->textarea('value', [
                        'class' => 'form-control ' . ($edit ? 'bg-secondary-subtle' : 'bg-light'),
                        'rows' => 10,
                        'required' => true,
                        'readonly' => $edit
                    ]) ?>
                </div>

                <!-- COMMENT -->
                <div class="mb-4">
                    <?= $this->Form->label('comment', __('Comment'), ['class' => 'form-label fw-semibold']) ?>

                    <?= $this->Form->textarea('comment', [
                        'class' => 'form-control bg-light',
                        'rows' => 4,
                        'required' => false
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
                        '<i class="fas fa-check me-1"></i> ' . ($edit ? __('Edit exclusion') : __('Add new exclusion')), 
                        [
                            'class' => 'btn btn-primary',
                            'escapeTitle' => false,
                            'title' => $edit ? __('Edit exclusion') : __('Add new exclusion'),
                            'aria-label' => $edit ? __('Edit exclusion') : __('Add new exclusion'),
                        ]
                    ) ?>
                </div>

            </div>

        </div>

    </div>

</div>

<?= $this->Form->end(); ?>