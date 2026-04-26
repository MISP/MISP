<?php
$tagName = $this->request->data['Taxonomy']['name'];

echo $this->Form->create('Taxonomy', [
    'class' => 'needs-validation',
    'novalidate' => true,
]);
?>

<div class="container me-5">
    <div class="row justify-content-center">
        <div class="card shadow-sm">
            <div class="card-body">

                <h3 class="mb-2">
                    <?= __('Confirm disabling Taxonomy Tag') ?>
                </h3>

                <!-- DESCRIPTION -->
                <p class="text-muted mb-4">
                    <?= __('Tag') ?> <strong><?= h($tagName) ?></strong>
                    <?= __('will be disabled.') ?>
                </p>

                <!-- HIDDEN FIELDS -->
                <?= $this->Form->hidden('taxonomy_id') ?>
                <?= $this->Form->hidden('name') ?>

                <!-- ACTIONS -->
                <div class="d-flex justify-content-end gap-3">
                    <button type="button"
                            class="btn btn-outline-secondary"
                            data-bs-dismiss="modal">
                        <?= __('Cancel') ?>
                    </button>

                    <?= $this->Form->button(
                        '<i class="fas fa-stop me-1"></i> ' . __('Disable Tag'),
                        [
                            'class' => 'btn btn-primary',
                            'escapeTitle' => false,
                            'title' => __('Disable Tag'),
                            'aria-label' => __('Disable Tag'),
                        ]
                    ) ?>
                </div>

            </div>
        </div>
    </div>
</div>

<?= $this->Form->end() ?>