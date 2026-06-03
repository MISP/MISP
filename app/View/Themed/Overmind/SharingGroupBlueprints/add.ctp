<?php
$edit = $this->request->params['action'] === 'edit';

echo $this->Form->create('SharingGroupBlueprint', [
    'class' => 'needs-validation',
    'novalidate' => true
]);
?>

<div class="container me-5">
    <div class="row justify-content-center">

        <div class="card shadow-sm">

            <div class="card-body">

                <!-- TITLE -->
                <h3 class="mb-2">
                    <?= $edit
                        ? __('Edit Sharing Group Blueprint')
                        : __('Create Sharing Group Blueprint') ?>
                </h3>

                <!-- DESCRIPTION -->
                <div class="alert alert-light border mb-4">

                    <p class="mb-2">
                        <?= __('Create reusable sharing group rules using nested JSON logic.') ?>
                    </p>

                    <div class="small text-muted">

                        <div class="mb-2">
                            <span class="fw-semibold"><?= __('Available filters') ?>:</span><br>
                            <code>
                                org_id, org_type, org_uuid, org_name,
                                org_sector, org_nationality,
                                sharing_group_id, sharing_group_uuid
                            </code>
                        </div>

                        <div>
                            <span class="fw-semibold"><?= __('Boolean operators') ?>:</span><br>
                            <code>AND, OR, NOT</code>
                        </div>

                    </div>

                </div>

                <!-- NAME -->
                <div class="mb-3">

                    <?= $this->Form->label(
                        'name',
                        __('Blueprint name'),
                        ['class' => 'form-label fw-semibold']
                    ) ?>

                    <?= $this->Form->control('name', [
                        'label' => false,
                        'class' => 'form-control bg-light',
                        'placeholder' => __('European financial institutions'),
                        'required' => true
                    ]) ?>

                </div>

                <!-- RULES -->
                <div class="mb-4">

                    <div class="d-flex justify-content-between align-items-center mb-2">

                        <?= $this->Form->label(
                            'rules',
                            __('Rules (JSON)'),
                            ['class' => 'form-label fw-semibold mb-0']
                        ) ?>

                        <span id="json-status"
                              class="badge bg-secondary">
                            <?= __('Waiting for input') ?>
                        </span>

                    </div>

                    <?= $this->Form->textarea('rules', [
                        'label' => false,
                        'rows' => 16,
                        'class' => 'form-control font-monospace bg-dark text-light border-secondary',
                        'placeholder' => "{\n    \"AND\": {\n        \"OR\": {\n            \"org_sector\": \"Financial\"\n        }\n    }\n}",
                        'spellcheck' => 'false',
                        'style' => 'white-space: pre; overflow-x: auto;'
                    ]) ?>


                    <div class="form-text">
                        <?= __('Rules must be valid JSON.') ?>
                    </div>

                </div>

                <!-- ACTIONS -->
                <div class="d-flex justify-content-end gap-3">

                    <button type="button"
                            class="btn btn-outline-secondary"
                            onclick="history.back()">
                        <?= __('Cancel') ?>
                    </button>

                    <?= $this->Form->button(
                        '<i class="fas fa-check me-1"></i> ' .
                        ($edit ? __('Save changes') : __('Create blueprint')),
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


<style>
    #SharingGroupBlueprintRules::placeholder {
        color: rgba(255, 255, 255, 0.65);
        opacity: 1;
    }

    #SharingGroupBlueprintRules {
        min-height: 350px;
        resize: vertical;
    }
</style>