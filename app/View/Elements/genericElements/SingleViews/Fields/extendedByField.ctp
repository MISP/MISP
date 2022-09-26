<?php
    $extended_by = [];
    $id = Hash::extract($data, $field['path'])[0];
    foreach ($field['extended_by'] as $extension) {
        $extended_by[] = sprintf('<span>%s (<a href="%s">%s</a>): %s</span>', __('Event'), $baseurl . '/events/view/' . h($extension['Event']['id']), h($extension['Event']['id']), h($extension['Event']['info']));
    }
    echo sprintf(
        '%s %s %s',
        implode('<br />', $extended_by),
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
