<?php
    $data = $this->DataPathCollector->extract($row, $field['data_path']);
    if ($data['Feed.enabled']) {
        if (in_array($data['Feed.source_format'], array('freetext', 'csv'))) {
            if ($data['Feed.fixed_event']) {
                if (!empty($data['Feed.event_error'])) {
                    echo sprintf(
                        '<span class="red bold">%s</span>',
                        __('Error: Invalid event!')
                    );
                } else {
                    if ($data['Feed.event_id']) {
                        echo sprintf(
                            '<a href="%s/events/view/%s">%s</a>',
                            $baseurl,
                            h($data['Feed.event_id']),
                            __('Fixed event %s', h($data['Feed.event_id']))
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
