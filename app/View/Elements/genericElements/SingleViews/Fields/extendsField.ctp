<?php
    if (!empty($field['extendedEvent']) && is_array($field['extendedEvent'])) {
        echo sprintf(
            '<span>%s (<a href="%s">%s</a>): %s</span>',
            __('Event'),
            $baseurl . '/events/view/' . h($extendedEvent[0]['Event']['id']),
            h($extendedEvent[0]['Event']['id']),
            h($extendedEvent[0]['Event']['info'])
        );
    } else {
        $value = Hash::extract($data, $field['path'])[0];
        echo h($value);
    }
