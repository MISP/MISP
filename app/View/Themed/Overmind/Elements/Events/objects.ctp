<?php
$objects = [];
foreach ($data['objects'] as $object) {
    if (isset($object['objectType']) && $object['objectType'] === 'object' && !empty($object['Attribute'])) {
        $objects[] = $object;
    }
}

// xdebug_break();
echo $this->element('Objects/index', [
    'attributes' => $objects,
]);