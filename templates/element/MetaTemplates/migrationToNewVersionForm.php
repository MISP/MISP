<?php
$formRandomValue = Cake\Utility\Security::randomString(8);

echo $this->Form->create($entity, ['id' => 'form-' . $formRandomValue]);
echo $this->element(
    'genericElements/Form/metaTemplateForm',
    [
        'metaTemplate' => $metaTemplate,
    ]
);
echo $this->Form->end();
?>