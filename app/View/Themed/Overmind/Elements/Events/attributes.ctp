<?php
$attributes = [];
foreach ($data['objects'] as $object) {
    if (isset($object['objectType']) && $object['objectType'] === 'attribute') {
        $attributes[] = $object;
    }
    if (isset($object['objectType']) && $object['objectType'] === 'object' && !empty($object['Attribute'])) {
        foreach ($object['Attribute'] as $attribute) {
            $attributes[] = $attribute;
        }
    }
}

echo $this->element('Attributes/index', [
    'attributes' => $attributes,
    'show_event_id' => false
]);


