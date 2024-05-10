<?php
    $htmlElements = [];
    if (!empty($event['Feed'])) {
        foreach ($event['Feed'] as $relatedFeed) {
            $relatedData = [
                __('Name') => $relatedFeed['name'],
                __('URL') => $relatedFeed['url'],
                __('Provider') => $relatedFeed['provider'],
            ];
            $popover = '';
            $canPivot = $relatedFeed['lookup_visible'] || $isSiteAdmin || $me['org_id'] == Configure::read('MISP.Host_org_id');
            foreach ($relatedData as $k => $v) {
                $popover .= sprintf(
                    '<span class="bold">%s</span>: <span class="blue">%s</span><br>',
                    h($k),
                    h($v)
                );
            }
            
            if (!$canPivot) {
                $popover .= sprintf(
                    '<span class="bold">%s</span>: <span class="blue">%s</span><br />',
                    __('Note'),
                    __('You don\'t have the required permissions to pivot to the details.')
                );
                if ($relatedFeed ['source_format'] === 'misp') {
                    $htmlElements[] = sprintf(
                        '<span data-toggle="popover" data-content="%s" data-trigger="hover">%s</span>',
                        h($popover),
                        h($relatedFeed['name']) . ' (' . $relatedFeed['id'] . ')'
                    );
                } else {
                    $htmlElements[] = sprintf(
                        '<span data-toggle="popover" data-content="%s" data-trigger="hover">%s</span><br>',
                        h($popover),
                        h($relatedFeed['name']) . ' (' . $relatedFeed['id'] . ')'
                    );
                }
            } else {
                if ($relatedFeed ['source_format'] === 'misp') {
                    $htmlElements[] = sprintf(
                        '<form action="%s/feeds/previewIndex/%s" method="post" style="margin:0px;">%s</form>',
                        h($baseurl),
                        h($relatedFeed['id']),
                        sprintf(
                            '<input type="hidden" name="data[Feed][eventid]" value="%s">
                            <input type="submit" class="linkButton useCursorPointer" value="%s" data-toggle="popover" data-content="%s" data-trigger="hover">',
                            h(json_encode($relatedFeed['event_uuids'] ?? [])),
                            h($relatedFeed['name']) . ' (' . $relatedFeed['id'] . ')',
                            h($popover)
                        )
                    );
                } else {
                    $htmlElements[] = sprintf(
                        '<a href="%s/feeds/previewIndex/%s" data-toggle="popover" data-content="%s" data-trigger="hover">%s</a><br>',
                        h($baseurl),
                        h($relatedFeed['id']),
                        h($popover),
                        h($relatedFeed['name']) . ' (' . $relatedFeed['id'] . ')'
                    );
                }
            }
        }
    } else {
        $htmlElements[] = sprintf(
            '<span>%s</span>',
            __(
                'This event has %s correlations with data contained within the various feeds, however, due to the large number of attributes the actual feed correlations are not shown. Click <a href="%s\/overrideLimit:1">here</a> to refresh the page with the feed data loaded.',
                h($event['Event']['FeedCount']),
                h(Router::url(null, true))
            )
        );
    }

    echo sprintf(
        '<h3>%s %s</h3><div class="inline correlation-container">%s</div>',
        __('Related Feeds'),
        sprintf(
            '<a href="#attributeList" title="%s" onclick="%s">%s</a>',
            __('Show just attributes that have feed hits'),
            "toggleBoolFilter('feed')",
            __('(show)')
        ),
        implode(PHP_EOL, $htmlElements)
    );
