<?php
/**
 * What a note or an opinion on a value hangs off, as one chip: the value
 * itself, an occurrence, its event (inherited), its object, a cluster, or
 * the item it replies to. Analyst data attaches to an object_uuid, never to
 * a value, so the chip says which record it is really about.
 *
 * @var array $target ValueIntelligence analyst item `attached_to`
 */
App::uses('ValueUrlTool', 'Tools/ValueIntelligence');

$event = isset($target['event']) ? '#' . $target['event'] : __('an event');
$eventUrl = empty($target['event']) ? null : $baseurl . '/events/view/' . (int)$target['event'];

$chip = function ($href, $title, $body, $extra = '') {
    $class = 'vpa-chip' . $extra . ($href === null ? '' : ' vpa-chip-link');
    if ($href === null) {
        return '<span class="' . $class . '" title="' . h($title) . '">' . $body . '</span>';
    }
    return '<a class="' . $class . '" href="' . h($href) . '" title="' . h($title) . '">' . $body
        . '<i class="fas fa-arrow-up-right-from-square" aria-hidden="true"></i></a>';
};
$sep = function ($text) {
    return '<span class="vpa-chip-sep">' . h($text) . '</span>';
};
$icon = function ($name) {
    return '<span class="misp-icon misp-icon-' . $name . ' misp-simple"></span>';
};

switch ($target['kind']) {
    case 'value':
        // Written on the value itself; another spelling opens that spelling's page.
        echo $target['spelled'] === null
            ? $chip(null, __('Written on this value itself, not on one of its occurrences.'),
                '<i class="fas fa-fingerprint" aria-hidden="true"></i>' . h(__('this value')))
            : $chip($baseurl . '/values/view/' . ValueUrlTool::address($target['spelled']),
                __('Written on this value in another spelling. Opens that spelling.'),
                '<i class="fas fa-fingerprint" aria-hidden="true"></i>' . h(__('this value'))
                    . $sep(__('spelled')) . h($target['spelled']));
        break;
    case 'event':
        echo $chip($eventUrl,
            __('Attached to the event, so it is inherited by every occurrence in it. Opens the event.'),
            $icon('event') . h($event) . $sep(__('inherited')));
        break;
    case 'object':
        echo $chip($eventUrl === null ? null : $eventUrl . '#tab-objects',
            __('Attached to the object the occurrence sits in. Opens the event, on its Objects tab.'),
            $icon('object') . h($target['name']) . $sep(__('in')) . $icon('event') . h($event));
        break;
    case 'reply':
        echo $chip(null,
            __('Attached to the item above: a statement about that item rather than about the value.'),
            $icon('analyst-note') . h(isset($target['to']) && $target['to'] === 'opinion'
                ? __('the opinion above') : __('the note above')));
        break;
    case 'cluster':
        echo $chip(empty($target['id']) ? null : $baseurl . '/galaxy_clusters/view/' . (int)$target['id'],
            __('Attached to a galaxy cluster this value is classified under, so it is inherited by everything else carrying it. Opens the cluster.'),
            $icon('galaxy') . h($target['name']) . $sep(__('cluster')));
        break;
    case 'unresolved':
        echo $chip(null,
            __('This item names a target that no longer resolves. It is shown because somebody wrote it.'),
            '<i class="fas fa-link-slash"></i>' . h(__('target does not resolve')),
            ' vpa-chip-unresolved');
        break;
    default:
        echo $chip($eventUrl === null ? null : $eventUrl . '#tab-attributes',
            __('Attached to one occurrence of this value. Opens the event, on its Attributes tab.'),
            $icon('attribute') . h($target['type'] ?? '') . $sep(__('in')) . $icon('event') . h($event));
}
