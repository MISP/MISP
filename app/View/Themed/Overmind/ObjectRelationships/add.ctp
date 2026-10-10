<?php
$isEdit = $this->request->params['action'] === 'edit';
$relationship = $this->request->data['ObjectRelationship'] ?? [];

echo $this->Form->create('ObjectRelationship', [
    'id' => 'objectRelationshipForm',
    'novalidate' => true,
]);

echo $this->element('genericElementsBS5/Forms/modal_header', [
    'accent' => 'object',
    'eyebrow' => __('Object Relationships'),
    'title' => $isEdit ? __('Edit Object Relationship') : __('Add Object Relationship'),
    'description' => __('A relationship type that objects can be linked with, such as "downloaded-from" or "contains".'),
    'icon' => 'fas fa-diagram-project',
    'isEdit' => $isEdit,
]);
?>

<div class="container-fluid px-4 py-4">

    <div class="d-flex flex-column gap-4">

        <!-- ── NAME ────────────────────────────────────────────── -->
        <div class="w-100 px-2">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'accent' => 'object',
                'label' => __('Name'),
                'required' => true,
            ]) ?>
            <?php
            /* Form->text(), not Form->control(): the latter is CakePHP 3 API and
             * fell through FormHelper::__call(), which silently dropped the
             * class and the placeholder. */
            echo $this->Form->text('name', [
                'id' => 'ObjectRelationshipName',
                'class' => 'w-100 border-0 bg-transparent fs-5 py-1',
                'style' => 'border-bottom:1px solid #d8dde3 !important; outline:none;',
                'placeholder' => __('e.g. downloaded-from'),
                'autocomplete' => 'off',
                'required' => true,
            ]);
            ?>
            <?= $this->element('genericElementsBS5/Forms/field_hint', [
                'text' => __('Lowercase and hyphenated, by convention.'),
            ]) ?>
        </div>

        <!-- ── DESCRIPTION ─────────────────────────────────────── -->
        <div class="w-100 px-2">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'accent' => 'object',
                'label' => __('Description'),
            ]) ?>
            <?= $this->Form->textarea('description', [
                'id' => 'ObjectRelationshipDescription',
                'class' => 'form-control',
                'style' => 'border-color:#d8dde3;',
                'rows' => 5,
                'placeholder' => __('What this relationship means between two objects'),
            ]) ?>
        </div>

        <!-- ── OPTIONS ─────────────────────────────────────────── -->
        <div class="w-100 px-2">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'accent' => 'object',
                'label' => __('Options'),
            ]) ?>
            <div class="form-check form-switch">
                <?= $this->Form->checkbox('highlighted', [
                    'class' => 'form-check-input',
                    'id' => 'ObjectRelationshipHighlighted',
                    'hiddenField' => true,
                    'checked' => !empty($highlighted),
                ]) ?>
                <?= $this->Form->label(
                    'ObjectRelationshipHighlighted',
                    __('Highlight this relationship'),
                    ['class' => 'form-check-label']
                ) ?>
            </div>
            <?= $this->element('genericElementsBS5/Forms/field_hint', [
                'text' => __('A highlighted relationship is offered first in the object reference picker.'),
            ]) ?>
        </div>

    </div>

    <?= $this->element('genericElementsBS5/Forms/modal_footer', [
        'accent' => 'object',
        'isEdit' => $isEdit,
        'meta' => $isEdit && !empty($relationship['id'])
            ? [['label' => __('Relationship'), 'id' => $relationship['id']]]
            : [],
        'submit' => ['label' => $isEdit ? __('Save Changes') : __('Add Relationship')],
    ]) ?>

</div>

<?= $this->Form->end() ?>
