<?php
$edit = $this->request->params['action'] === 'admin_edit' ? true : false;

echo $this->Form->create('Allowedlist', [
    'class' => 'needs-validation',
    'novalidate' => true
]);

?>

<div class="container me-5">

    <div class="row justify-content-center">

        <div class="card shadow-sm">

            <div class="card-body">

                <h3 class="mb-2">
                    <?=  $edit ? __('Edit current allowedlist') : __('Create New Allowedlist')  ?>
                </h3>

                <div class="form-text mb-2">
                        <?= __('Regex entries (in the standard php regex /{regex}/{modifier} format) entered below will restrict matching attributes from being included in the IDS flag sensitive exports (such as NIDS exports).')?>
                </div>

                <!-- NAME -->
                <div class="mb-3">
                    <?= $this->Form->label('name', __('Name'), ['class' => 'form-label fw-semibold']) ?>

                    <?= $this->Form->textarea('name', [
                        'label' => false,
                        'class' => 'form-control bg-light',
                        'placeholder' => '',
                        'rows' => 8,
                        'required' => true
                    ]) ?>

                    <div class="form-text">
                        <?= __('Allowedlist entries have to be enclosed by a valid php delimiter (which can be most non-alphanumeric / non-whitespace character). Format: "/8.8.8.8/" Please double check the name.') ?>
                <div class="d-flex justify-content-end gap-3">
                    <button type="button"
                            class="btn btn-outline-secondary"
                            data-bs-dismiss="modal">
                        <?= __('Cancel') ?>
                    </button>
                    <?= $this->Form->button(
                        '<i class="fas fa-check me-1"></i> ' . ($edit ? __('Edit allowedlist') : __('Add new allowedlist')), 
                        [
                            'class' => 'btn btn-primary',
                            'escapeTitle' => false,
                            'title' => $edit ? __('Edit allowedlist') : __('Add new allowedlist'),
                            'aria-label' => $edit ? __('Edit allowedlist') : __('Add new allowedlist'),
                        ]
                    ) ?>
                </div>

            </div>

        </div>

    </div>

</div>

<?= $this->Form->end(); ?>