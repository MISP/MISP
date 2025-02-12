<?php
    if (!empty($field['extendedEvent']) && is_array($field['extendedEvent'])) {
        $extendButton = sprintf(
            '<a href="%s" style="margin-left: 0.5em;"><span class="fa fa-sync" title="%s"></span></a>',
            sprintf(
                '%s/events/view/%s%s',
                $baseurl,
                h($data['Event']['id']),
                ($field['extending'] ? '' : '/extending:1')
            ),
            $field['extending'] ? __('Switch to atomic view') : __('Switch to extending view')
        );
        echo sprintf(
            '<div>%s (<a href="%s">%s</a>): %s %s</div>',
            __('Event'),
            $baseurl . '/events/view/' . h($extendedEvent[0]['Event']['id']),
            h($extendedEvent[0]['Event']['id']),
            h($extendedEvent[0]['Event']['info']),
            $extendButton
        );
        echo sprintf('<div style="padding-left: 1.0em;"><span class="apply_css_arrow"><strong style="font-size: larger;">%s</strong></span></div>', h($data['Event']['info']));
    } else {
        $value = Hash::extract($data, $field['path'])[0];
        echo h($value);
    }
