<?php
    $extended_by = [];
    $id = Hash::extract($data, $field['path'])[0];
    foreach ($field['extended_by'] as $extension) {
        $extended_by[] = sprintf('<div style="padding-left: 1.0em;"><span class="apply_css_arrow">%s (<a href="%s">%s</a>): %s</span></div>', __('Event'), $baseurl . '/events/view/' . h($extension['Event']['id']), h($extension['Event']['id']), h($extension['Event']['info']));
    }
    echo sprintf('<div><strong style="font-size: larger;">%s</strong></div>', h($data['Event']['info']));
    echo sprintf(
        '%s %s %s',
        implode('', $extended_by),
        __(
            'Currently in %s view.',
            $field['extended'] ? __('extended') : __('atomic')
        ),
        sprintf(
            '<a href="%s"><span class="fa fa-sync" title="%s"></span></a>',
            sprintf(
                '%s/events/view/%s%s',
                $baseurl,
                h($id),
                ($field['extended'] ? '' : '/extended:1')
            ),
            $field['extended'] ? __('Switch to atomic view') : __('Switch to extended view')
        )
    );
