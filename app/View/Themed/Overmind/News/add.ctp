<?php
$edit = $this->request->params['action'] === 'edit' ? true : false;

echo $this->Form->create('News', [
    'class' => 'needs-validation',
    'novalidate' => true
]);
?>

<div class="container me-5">

    <div class="row justify-content-center">

        <div class="card shadow-sm">

            <div class="card-body">

                <h3 class="mb-2">
                    <?= $edit ? __('Edit news item') : __('Add news item') ?>
                </h3>

                <div class="form-text mb-3">
                    <?= __('News items are shown to users on the News page. New items are highlighted until the user reads them.') ?>
                </div>

                <!-- TITLE -->
                <div class="mb-3">
                    <?= $this->Form->label('title', __('Title'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->text('title', ['class' => 'form-control', 'required' => true]) ?>
                </div>

                <!-- MESSAGE -->
                <div class="mb-3">
                    <?= $this->Form->label('message', __('Message'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->textarea('message', ['class' => 'form-control', 'rows' => 8]) ?>
                    <div class="form-text"><?= __('You can use Markdown format.') ?></div>
                </div>

                <!-- ANONYMISE -->
                <div class="mb-4 form-check">
                    <?= $this->Form->checkbox('anonymise', ['class' => 'form-check-input', 'id' => 'NewsAnonymise']) ?>
                    <?= $this->Form->label('anonymise', __('Create anonymously'), ['class' => 'form-check-label', 'for' => 'NewsAnonymise']) ?>
                    <div class="form-text"><?= __('When set, the news item is not attributed to your account.') ?></div>
                </div>

                <!-- ACTIONS -->
                <div class="d-flex justify-content-end gap-3">
                    <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">
                        <?= __('Cancel') ?>
                    </button>
                    <?= $this->Form->button(
                        '<i class="fas fa-check me-1"></i> ' . ($edit ? __('Save changes') : __('Add news item')),
                        [
                            'class' => 'btn btn-primary',
                            'escapeTitle' => false,
                            'title' => $edit ? __('Save changes') : __('Add news item'),
                            'aria-label' => $edit ? __('Save changes') : __('Add news item'),
                        ]
                    ) ?>
                </div>

            </div>

        </div>

    </div>

</div>

<?= $this->Form->end(); ?>
