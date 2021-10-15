<?php

$object = Hash::extract($row, $field['data']['object']['value_path']);
$event = Hash::extract($row, 'Event');

if (!empty($object['RelatedAttribute'])) {
    $event['RelatedAttribute'] = array($object['id'] => $object['RelatedAttribute']);
}

if (!empty($event['RelatedAttribute'][$object['id']])) {
    echo '<ul class="inline" style="margin:0">';
    echo $this->element('Events/View/attribute_correlations', array(
        'scope' => $field['data']['scope'],
        'object' => $object,
        'event' => $event,
    ));
    echo '</ul>';
}
