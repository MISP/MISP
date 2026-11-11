<?php
$types = is_array($model['attribute_types'] ?? null) ? $model['attribute_types'] : [];
sort($types);

echo $this->Form->create('DecayingModelMapping', [
    'id' => 'decayingModelMappingForm',
    'url' => $baseurl . '/decayingModelMapping/linkAttributeTypeToModel/' . (int)$model_id,
    'novalidate' => true,
]);

echo $this->element('genericElementsBS5/Forms/modal_header', [
    'eyebrow' => __('Decaying Models'),
    'title' => __('Edit attribute type mapping'),
    'description' => __('The attribute types this model scores. The list replaces the current mapping.'),
    'icon' => 'fas fa-hourglass-half',
    'isEdit' => true,
]);
?>

<div class="container-fluid px-4 py-4">

    <?= $this->element('genericElementsBS5/Forms/json_field', [
        'field' => 'DecayingModelMapping.attributetypes',
        'label' => __('Attribute types (JSON)'),
        'shape' => 'array',
        'required' => true,
        'id' => 'DecayingModelMappingAttributetypes',
        'value' => $types,
        'reset' => $types,
        'placeholder' => '["ip-src", "ip-dst", "domain"]',
        'rows' => 14,
        'minHeight' => '320px',
    ]) ?>

    <?= $this->element('genericElementsBS5/Forms/modal_footer', [
        'isEdit' => true,
        'meta' => [['label' => __('Model'), 'id' => $model_id]],
    ]) ?>

</div>

<?= $this->Form->end() ?>
