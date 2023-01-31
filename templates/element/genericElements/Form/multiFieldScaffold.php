<?php

use Cake\Utility\Inflector;

$default_template = [
    'inputContainer' => '<div class="row mb-1 multi-metafield-container">{{content}}</div>',
    'inputContainerError' => '<div class="row mb-1 multi-metafield-container has-error">{{content}}</div>',
    'formGroup' => '<label class="col-sm-2 col-form-label form-label" {{attrs}}>{{label}}</label><div class="col-sm-10 multi-metafield-input-container">{{input}}{{error}}</div>',
];
$form->setTemplates($default_template);

$fieldsHtml = '';
$labelPrintedOnce = false;
if (!empty($metaFieldsEntities)) {
    foreach ($metaFieldsEntities as $i => $metaFieldsEntity) {
        $metaFieldsEntity->label = Inflector::humanize($metaFieldsEntity->field);
        $fieldData = [
            'label' => $metaFieldsEntity->label,
            'field' => sprintf(
                'MetaTemplates.%s.meta_template_fields.%s.metaFields.%s.value',
                $metaFieldsEntity->meta_template_id,
                $metaFieldsEntity->meta_template_field_id,
                $metaFieldsEntity->id
            ),
            'type' => $metaTemplateField->formType,
        ];
        if($metaFieldsEntity->isNew()) {
            $fieldData['field'] = sprintf(
                'MetaTemplates.%s.meta_template_fields.%s.metaFields.%s.value',
                $metaFieldsEntity->meta_template_id,
                $metaFieldsEntity->meta_template_field_id,
                $i
            );
            $fieldData['class'] = 'new-metafield';
        }
        if ($labelPrintedOnce) { // Only the first input can have a label
            $fieldData['label'] = ['text' => ''];
        }
        if ($metaTemplateField->formType === 'dropdown') {
            $fieldData = array_merge_recursive($fieldData, $metaTemplateField->formOptions);
        }
        $labelPrintedOnce = true;
        $fieldsHtml .= $this->element(
            'genericElements/Form/fieldScaffold',
            [
                'fieldData' => $fieldData,
                'form' => $form
            ]
        );
    }
}
if (!empty($metaTemplateField) && !empty($multiple)) { // Add multiple field button
    $metaTemplateField->label = Inflector::humanize($metaTemplateField->field);
    $emptyMetaFieldInput = '';
    if (empty($metaFieldsEntities)) { // Include editable field for meta-template not containing a meta-field
        $fieldData = [
            'label' => $metaTemplateField->label,
            'field' => sprintf('MetaTemplates.%s.meta_template_fields.%s.metaFields.new.0', $metaTemplateField->meta_template_id, $metaTemplateField->id),
            'class' => 'new-metafield',
            'type' => $metaTemplateField->formType,
        ];
        if ($metaTemplateField->formType === 'dropdown') {
            $fieldData = array_merge_recursive($fieldData, $metaTemplateField->formOptions);
        }
        $emptyMetaFieldInput = $this->element(
            'genericElements/Form/fieldScaffold',
            [
                'fieldData' => $fieldData,
                'form' => $form,
            ]
        );
    }
    $emptyInputForSecurityComponent = $this->element(
        'genericElements/Form/fieldScaffold',
        [
            'fieldData' => [
                'label' => false,
                'field' => sprintf('MetaTemplates.%s.meta_template_fields.%s.metaFields.new[]', $metaTemplateField->meta_template_id, $metaTemplateField->id),
                'value' => '',
            ],
            'form' => $form,
        ]
    );
    $multiFieldButtonHtml = sprintf(
        '<div class="row mb-1 multi-metafield-container add-input-container"><div class="col-sm-2 form-label"></div><div class="col-sm-10 multi-metafield-input-container">%s</div></div>',
        $this->element(
            'genericElements/Form/multiFieldButton',
            [
                'metaTemplateFieldName' => $metaTemplateField->field,
            ]
        )
    );
    $fieldsHtml .= $emptyMetaFieldInput;
    $fieldsHtml .= sprintf('<div class="d-none template-container">%s</div>', $emptyInputForSecurityComponent);
    $fieldsHtml .= $multiFieldButtonHtml;
}
?>

<div class="row mb-3 multi-metafields-container">
    <?= $fieldsHtml; ?>
</div>