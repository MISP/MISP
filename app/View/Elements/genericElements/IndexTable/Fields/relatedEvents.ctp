<?php
    $object = Hash::extract($row, $field['data']['object']['value_path']);
    $event = Hash::extract($row, 'Event');
    if (!empty($object['RelatedAttribute'])) {
        $event['RelatedAttribute'] = array($object['id'] => $object['RelatedAttribute']);
    }
    foreach ($event['RelatedAttribute'] as $k => &$ra) {
        if (!empty($ra['Event'])) {
            $ra['info'] = $ra['Event']['info'];
            $ra['org_id'] = $ra['Event']['org_id'];
        }
    }
    echo sprintf(
        '<ul class="inline" style="margin:0">%s</ul>',
        $this->element('Events/View/attribute_correlations', [
            'scope' => $field['data']['scope'],
            'object' => $object,
            'event' => $event,
        ])
    );
