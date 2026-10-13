<?php
/**
 * Where a drawn row came from.
 *
 * On the value page the sources are the modules that answered, printed as
 * they are. On the event page the object views set `vpEventScope` and the
 * sources are object UUIDs: each prints as the object, linked when the
 * drawing is full, with its event when it is not the one being viewed.
 *
 * @var array|string|null $sources
 */
$sources = array_values(array_filter((array)($sources ?? array())));
$scope = $this->viewVars['vpEventScope'] ?? null;
if ($scope === null) {
    echo h(implode(', ', $sources));
    return;
}
App::uses('EventObjectViewsTool', 'Tools/EventOverview');
foreach ($sources as $i => $uuid) {
    if ($i > 0) {
        echo ', ';
    }
    $origin = $scope['origins'][$uuid] ?? null;
    if ($origin === null) {
        echo '—';
        continue;
    }
    $name = $origin['template'] . ' #' . $origin['object_id'];
    $label = $origin['label'] !== null && $origin['label'] !== ''
        ? $origin['label'] : $name;
    $title = $name . ($label !== $name ? ' · ' . $label : '');
    $short = EventObjectViewsTool::shorten($label, 28);
    if (!empty($scope['link'])) {
        printf(
            '<a class="eov-src" href="%s" title="%s">%s</a>',
            h($scope['baseurl'] . '/objects/view/' . $origin['object_id']),
            h($title),
            h($short)
        );
    } else {
        printf(
            '<span class="eov-src" title="%s">%s</span>',
            h($title),
            h($short)
        );
    }
    if ((int)$origin['event_id'] !== (int)$scope['event_id']) {
        echo ' ' . $this->element('Events/View/ObjectViews/event_badge', array(
            'eventId' => $origin['event_id'],
            'link' => !empty($scope['link']),
        ));
    }
}
