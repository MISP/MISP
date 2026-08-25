<?php
$isEdit = $this->request->params['action'] === 'edit';
$blueprint = $this->request->data['WorkflowBlueprint'] ?? [];

/*
 * An import that fails validation lands back here with the offending values
 * already filled in, so the errors are surfaced above the fields.
 */
$errors = $this->validationErrors['WorkflowBlueprint'] ?? [];

echo $this->Form->create('WorkflowBlueprint', [
    'id' => 'workflowBlueprintForm',
    'novalidate' => true,
]);

echo $this->element('genericElementsBS5/Forms/modal_header', [
    'eyebrow' => __('Workflow Blueprints'),
    'title' => $isEdit ? __('Edit Workflow Blueprint') : __('Add Workflow Blueprint'),
    'description' => __('A re-usable block of workflow logic. The data field holds the blueprint graph as JSON — normally produced by the workflow editor.'),
    'icon' => 'fas fa-puzzle-piece',
    'isEdit' => $isEdit,
]);
?>

<div class="container-fluid px-4 py-4">

    <div class="d-flex flex-column gap-4">

        <?php if (!empty($errors)): ?>
            <div class="alert alert-danger py-2 mb-0" role="alert">
                <div class="fw-semibold mb-1">
                    <i class="fas fa-circle-exclamation me-1"></i>
                    <?= __('The blueprint could not be saved.') ?>
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

        <!-- ── NAME ────────────────────────────────────────────── -->
        <div class="w-100 px-2">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'label' => __('Name'),
                'required' => true,
            ]) ?>
            <?= $this->Form->text('name', [
                'id' => 'WorkflowBlueprintName',
                'class' => 'w-100 border-0 bg-transparent fs-5 py-1',
                'style' => 'border-bottom:1px solid #d8dde3 !important; outline:none;',
                'placeholder' => __('e.g. Enrich and tag on publish'),
                'autocomplete' => 'off',
                'required' => true,
            ]) ?>
        </div>

        <!-- ── DESCRIPTION ─────────────────────────────────────── -->
        <div class="w-100 px-2">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'label' => __('Description'),
            ]) ?>
            <?= $this->Form->textarea('description', [
                'id' => 'WorkflowBlueprintDescription',
                'class' => 'form-control',
                'style' => 'border-color:#d8dde3;',
                'rows' => 3,
                'placeholder' => __('What this blueprint does, in one or two lines'),
            ]) ?>
        </div>

        <!-- ── GRAPH ───────────────────────────────────────────── -->
        <div class="w-100 px-2">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'label' => __('Data (JSON)'),
            ]) ?>
            <?= $this->Form->textarea('data', [
                'id' => 'WorkflowBlueprintData',
                'class' => 'w-100 rounded-2 p-3',
                'style' => 'background:var(--bs-tertiary-bg, #f8f9fa);'
                    . ' border:1px solid #d8dde3; resize:vertical; outline:none;'
                    . ' font-size:.85rem; min-height:180px; color:inherit;'
                    . ' font-family:monospace;',
                'rows' => 10,
                'spellcheck' => 'false',
                'placeholder' => '[]',
            ]) ?>
            <?= $this->element('genericElementsBS5/Forms/field_hint', [
                'text' => __('The blueprint graph as a JSON array of blocks. Build it in the workflow editor and paste it here.'),
            ]) ?>
        </div>

    </div>

    <?= $this->element('genericElementsBS5/Forms/modal_footer', [
        'isEdit' => $isEdit,
        'meta' => $isEdit && !empty($id) ? [['label' => __('Blueprint'), 'id' => $id]] : [],
        'hint' => __('A blueprint does nothing on its own — attach it from the workflow editor.'),
        'submit' => ['label' => $isEdit ? __('Save Changes') : __('Add Blueprint')],
    ]) ?>

</div>

<?= $this->Form->end() ?>
