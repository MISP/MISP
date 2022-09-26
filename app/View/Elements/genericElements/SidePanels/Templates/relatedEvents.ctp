<?php
    $htmlElements = [];
    $count = 0;
    $displayThreshold = 10;
    $total = count($event['RelatedEvent']);
    foreach ($event['RelatedEvent'] as $relatedEvent) {
        $count++;
        $htmlElements[] = $this->element('/Events/View/related_event', [
            'related' => $relatedEvent['Event'],
            'ownOrg' => $relatedEvent['Event']['orgc_id'] == $me['org_id'],
            'hide' => $count > $displayThreshold,
            'relatedEventCorrelationCount' => $relatedEventCorrelationCount,
            'fromEventId' => $event['Event']['id']
        ]);
    }
    if ($total > $displayThreshold) {
        $htmlElements[] = sprintf(
            '<div class="%s">%s</div>',
            'expand-link linkButton blue',
            __('Show (%s more)', $total - $displayThreshold)
        );
        $htmlElements[] = sprintf(
            '<div class="%s">%s</div>',
            'collapse-link linkButton blue hidden',
            __('Collapse…')
        );
    }

    $select = sprintf('<select><option value="date">%s</option><option value="count">%s</option></select>',
        __("Order by date"),
        __("Order by count")
    );

    echo sprintf(
        '<div id="event-correlations">%s<h3>%s</h3><div class="clear correlation-container">%s</div></div>',
        $select,
        __('Related Events'),
        implode(PHP_EOL, $htmlElements)
    );
