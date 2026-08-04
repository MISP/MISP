<?php
$enable = !empty($this->request->params['named']['enable']);
$update = !empty($this->request->params['named']['update']);
$tagName = $this->request->data['Taxonomy']['name'];

$actionLabel = $enable ? __('Enabled') : ($update ? __('Updated') : __('Created'));
$actionIcon  = $enable ? 'fa-toggle-on' : ($update ? 'fa-pen' : 'fa-plus');

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
                    <?= $enable ? __('Confirm enabling Taxonomy Tag') : __('Confirm creation of Taxonomy Tag') ?>
                </h3>

                <!-- DESCRIPTION -->
                <p class="text-muted mb-4">
                    <?= __('Tag') ?> <strong><?= h($tagName) ?></strong>
                    <?= __('will be') ?> <span><?= strtolower($actionLabel) ?></span>.
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
                        '<i class="fas ' . $actionIcon . ' me-1"></i> ' . $actionLabel . ' ' . __('Tag'),
                        [
                            'class' => 'btn btn-primary',
                            'escapeTitle' => false,
                            'title' => $actionLabel . ' ' . __('Tag'),
                            'aria-label' => $actionLabel . ' ' . __('Tag'),
                        ]
                    ) ?>
                </div>

            </div>
        </div>
    </div>
</div>

<?= $this->Form->end() ?>