<?php
    $htmlElements = [];
    $count = 0;
    $display_threshold = 10;
    $total = count($event['RelatedEvent']);
    foreach ($event['RelatedEvent'] as $relatedEvent) {
        $count++;
        if ($count == $display_threshold+1 && $total > $display_threshold) {
            $htmlElements[] = sprintf(
                '<div class="%s">%s</div>',
                'no-side-padding correlation-expand-button useCursorPointer linkButton blue',
                __('Show (%s more)', $total - ($count-1))
            );
        }
        $htmlElements[] = $this->element('/Events/View/related_event', array(
            'related' => $relatedEvent['Event'],
            'color_red' => $relatedEvent['Event']['orgc_id'] == $me['org_id'],
            'hide' => $count > $display_threshold,
            'relatedEventCorrelationCount' => $relatedEventCorrelationCount,
            'from_id' => $event['Event']['id']
        ));
    }
    if ($total > $display_threshold) {
        $htmlElements[] = sprintf(
            '<div class="%s" style="display:none;">%s</div>',
            'no-side-padding correlation-collapse-button useCursorPointer linkButton blue',
            'display:none',
            __('Collapse…')
        );
    }

    echo sprintf(
        '<h3>%s</h3><div class="inline correlation-container">%s</div>',
        __('Related Events'),
        implode(PHP_EOL, $htmlElements)
    );
