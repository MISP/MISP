<?php
    $serverHtml = [];
    if (!empty($event['Server'])) {
        foreach ($event['Server'] as $relatedServer) {
            if (empty($relatedServer['id'])) {
                continue;
            }
            $relatedData = [
                'Name' => $relatedServer['name'],
                'URL' => $relatedServer['url']
            ];
            $popover = '';
            foreach ($relatedData as $k => $v) {
                $popover .= sprintf(
                    '<span class="bold">%s</span>: <span class="blue">%s</span><br />',
                    h($k),
                    h($v)
                );
                $serverHtml[] = sprintf(
                    '<span style="white-space: nowrap; display: inline-block">%s</span>',
                    sprintf(
                        '<a href="%s/servers/previewIndex/%s" class="linkButton useCursorPointer" data-toggle="popover" data-content="%s" data-trigger="hover">%s</a>&nbsp;',
                        $baseurl,
                        h($relatedServer['id']),
                        h($popover),
                        h($relatedServer['name']) . ' (' . $relatedServer['id'] . ')'
                    )
                );
            }
        }
    } else {
        $relatedData[] = __(
            'This event has %s correlations with data contained within the various feeds, however, due to the large number of attributes the actual feed correlations are not shown. Click %s to refresh the page with the feed data loaded.',
            sprintf(
                '<span class="bold">%s</span>',
                h($event['Event']['FeedCount'])
            ),
            sprintf(
                '<a href="%s\/overrideLimit:1">%s</a>',
                h(Router::url(null, true)),
                __('here')
            )
        );
    }
    echo sprintf(
        '<div class="correlation-container" style="margin-bottom: 15px;">%s</div>',
        implode(PHP_EOL, $serverHtml)
    );
