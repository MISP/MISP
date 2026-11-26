<?php
$runUrl = $this->request->here(false);
echo $this->Form->create('Workflow', [
    'id' => 'PromptForm',
    'url' => $runUrl,
    'class' => 'm-0',
]);
?>

<div class="d-flex justify-content-center">
    <div class="card shadow-sm d-inline-block w-auto" style="max-width: 34rem;">
        <div class="card-header">
            <h4 class="card-title mb-2 mt-2"><?= __('Execute Workflow') ?></h4>
        </div>

        <div class="card-body">
            <p class="mb-3">
                <?= __('The workflow runs immediately, with the site-admin privileges of the host organisation.') ?>
            </p>

            <div class="mb-3">
                <?= $this->element('genericElementsBS5/Forms/json_field', [
                    'field' => 'data',
                    'label' => __('Passed data (JSON)'),
                    'shape' => 'array',
                    'value' => '[]',
                    'rows' => 5,
                    'minHeight' => '130px',
                    'hint' => __('Leave as [] when the trigger collects its own data.'),
                ]) ?>
            </div>

            <div class="d-flex justify-content-between align-items-center">
                <button type="submit" class="btn btn-primary">
                    <i class="fas fa-play me-1"></i><?= __('Run') ?>
                </button>
                <button type="button" class="btn btn-outline-secondary"
                        onclick="bootstrap.Modal.getInstance(document.getElementById('mainModal')).hide();">
                    <?= __('Cancel') ?>
                </button>
            </div>
        </div>
    </div>
</div>

<?= $this->Form->end(); ?>
