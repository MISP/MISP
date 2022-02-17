<?php
$feed = $row['Feed'];
if ($feed['enabled']) {
    if (in_array($feed['source_format'], array('freetext', 'csv'))) {
        if ($feed['fixed_event']) {
            if (!empty($feed['event_error'])) {
                echo sprintf(
                    '<span class="red bold">%s</span>',
                    __('Error: Invalid event!')
                );
            } else {
                if ($feed['event_id']) {
                    echo sprintf(
                        '<a href="%s/events/view/%s">%s</a>',
                        $baseurl,
                        h($feed['event_id']),
                        __('Fixed event %s', h($feed['event_id']))
                    );
                } else {
                    echo __('New fixed event');
                }
            }
        } else {
            echo sprintf(
                '<span class="bold red" title="%s">%s</span>',
                __('New event each pull can lead to potentially endlessly growing correlation tables. Only use this setting if you are sure that the data in the feed will mostly be completely distinct between each individual pull, otherwise use fixed events. Generally this setting is NOT recommended.'),
                __('New event each pull')
            );
        }
    }
} else {
    echo __('Feed not enabled');
}
