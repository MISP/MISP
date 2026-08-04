<?php
/**
 * AJAX-loaded related events for view2 side panel.
 * Reuses the existing related_event element for
 * consistent look and feel.
 *
 * Variables: $relatedEvents, $correlationCounts, $event
 */
if (empty($relatedEvents)):
?>
    <em><?= __('No correlated events found.') ?></em>
<?php
    return;
endif;

$displayThreshold = 10;
$total = count($relatedEvents);
$count = 0;
$htmlElements = [];

foreach ($relatedEvents as $re) {
    $count++;
    $related = $re['Event'];
    $related['Orgc'] = $re['Event']['Orgc'] ?? [];
    $htmlElements[] = $this->element(
        '/Events/View/related_event',
        [
            'related' => $related,
            'ownOrg' => (
                isset($related['orgc_id']) &&
                $related['orgc_id'] == $me['org_id']
            ),
            'hide' => $count > $displayThreshold,
            'relatedEventCorrelationCount' =>
                $correlationCounts,
            'fromEventId' => $event['Event']['id'],
        ]
    );
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

$select = sprintf(
    '<select>'
    . '<option value="date">%s</option>'
    . '<option value="count">%s</option>'
    . '</select>',
    __('Order by date'),
    __('Order by count')
);

echo sprintf(
    '<div id="event-correlations">'
    . '%s<h3>%s</h3>'
    . '<div class="clear correlation-container">'
    . '%s</div></div>',
    $select,
    __('Related Events'),
    implode(PHP_EOL, $htmlElements)
);
