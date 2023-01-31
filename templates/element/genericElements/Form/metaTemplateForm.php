<?php

use Cake\Utility\Inflector;

$default_template = [
    'inputContainer' => '<div class="row mb-3 metafield-container">{{content}}</div>',
    'inputContainerError' => '<div class="row mb-3 metafield-container has-error">{{content}}</div>',
    'formGroup' => '<label class="col-sm-2 col-form-label form-label" {{attrs}}>{{label}}</label><div class="col-sm-10">{{input}}{{error}}</div>',
    'error' => '<div class="error-message invalid-feedback d-block">{{content}}</div>',
    'errorList' => '<ul>{{content}}</ul>',
    'errorItem' => '<li>{{text}}</li>',
];
$this->Form->setTemplates($default_template);
$backupTemplates = $this->Form->getTemplates();

$fieldsHtml = '';
foreach ($metaTemplate->meta_template_fields as $metaTemplateField) {
    $metaTemplateField->label = Inflector::humanize($metaTemplateField->field);
    if (!empty($metaTemplateField->metaFields)) {
        if (!empty($metaTemplateField->multiple)) {
            $fieldsHtml .= $this->element(
                'genericElements/Form/multiFieldScaffold',
                [
                    'metaFieldsEntities' => $metaTemplateField->metaFields,
                    'metaTemplateField' => $metaTemplateField,
                    'multiple' => !empty($metaTemplateField->multiple),
                    'form' => $this->Form,
                ]
            );
        } else {
            $metaField = reset($metaTemplateField->metaFields);
            $fieldData = [
                'label' => $metaTemplateField->label,
                'type' => $metaTemplateField->formType,
            ];
            if (!empty($metaTemplateField->formOptions)) {
                $fieldData = array_merge_recursive($fieldData, $metaTemplateField->formOptions);
            }
            if (isset($metaField->id)) {
                $fieldData['field'] = sprintf('MetaTemplates.%s.meta_template_fields.%s.metaFields.%s.value', $metaField->meta_template_id, $metaField->meta_template_field_id, $metaField->id);
            } else {
                $fieldData['field'] = sprintf('MetaTemplates.%s.meta_template_fields.%s.metaFields.%s.value', $metaField->meta_template_id, $metaField->meta_template_field_id, array_key_first($metaTemplateField->metaFields));
            }
            $this->Form->setTemplates($backupTemplates);
            $fieldsHtml .= $this->element(
                'genericElements/Form/fieldScaffold',
                [
                    'fieldData' => $fieldData,
                    'metaTemplateField' => $metaTemplateField,
                    'form' => $this->Form
                ]
            );
        }
    } else {
        if (!empty($metaTemplateField->multiple)) {
            $fieldsHtml .= $this->element(
                'genericElements/Form/multiFieldScaffold',
                [
                    'metaFieldsEntities' => [],
                    'metaTemplateField' => $metaTemplateField,
                    'multiple' => !empty($metaTemplateField->multiple),
                    'form' => $this->Form,
                ]
            );
        } else {
            $this->Form->setTemplates($backupTemplates);
            $fieldData = [
                'field' => sprintf('MetaTemplates.%s.meta_template_fields.%s.metaFields.new.0', $metaTemplateField->meta_template_id, $metaTemplateField->id),
                'label' => $metaTemplateField->label,
                'type' => $metaTemplateField->formType,
            ];
            if (!empty($metaTemplateField->formOptions)) {
                $fieldData = array_merge_recursive($fieldData, $metaTemplateField->formOptions);
            }
            $fieldsHtml .= $this->element(
                'genericElements/Form/fieldScaffold',
                [
                    'fieldData' => $fieldData,
                    'form' => $this->Form
                ]
            );
        }
    }
}
$fieldContainer = $this->Bootstrap->genNode('div', [
    'class' => [],
], $fieldsHtml);
echo $fieldContainer;