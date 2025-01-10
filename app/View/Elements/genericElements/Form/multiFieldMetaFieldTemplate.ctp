<?php
if (!empty($metaTemplateField)) {
    $fieldData = [
        'label' => false,
        'field' => sprintf('MetaTemplates.%s.meta_template_fields.%s.{count}', $metaTemplateField['meta_template_id'], $metaTemplateField['id']),
        'class' => 'metafield-template',
    ];
    echo $this->element(
        'genericElements/Form/fieldScaffold',
        [
            'fieldData' => $fieldData,
            'form' => $form
        ]
    );
}
