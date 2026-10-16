<?php
/**
 * The overview's galaxy matrix rail card: per matrix galaxy the event uses,
 * its tactics stacked with the techniques found on the event or on its
 * indicators.
 *
 * $matrix as EventsController::viewEventMatrix() builds it.
 */
$eventId = (int)$event['Event']['id'];
$suffix = $extensionSuffix ?? '';
echo $this->element('GalaxyMatrix/card', [
    'matrix' => $matrix,
    'texts' => [
        'onEvent' => __('On the event'),
        'onlyOne' => __('Only on 1 indicator'),
        'onlyMany' => __('Only on %s indicators'),
        'onOne' => __('On 1 indicator'),
        'onMany' => __('On %s indicators'),
        'showOne' => __('Show the indicator'),
        'showMany' => __('Show the %s indicators'),
    ],
    'fullUrl' => $baseurl . '/events/viewEventGalaxyMatrix/' . $eventId . '/%s' . $suffix,
    'rollupUrl' => $baseurl . '/events/viewEventMatrix/' . $eventId . $suffix . '/rollup:1',
    'lightIcon' => 'misp-icon misp-icon-attribute misp-simple',
]);
