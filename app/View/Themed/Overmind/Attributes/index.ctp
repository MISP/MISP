<?php
echo $this->element('genericElements/assetLoader', [
    'css' => ['attributes-index'],
]);
echo $this->element('Attributes/index', [
    'attributes' => $attributes,
    'show_event_id' => true,
    'show_filters' => true,
]);