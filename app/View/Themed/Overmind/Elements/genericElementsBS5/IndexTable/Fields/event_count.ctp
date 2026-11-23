<?php
// Overmind events index: one count (`count`: attributes, objects, reports, correlations).
// `pending`: a count the page fills in later (the feed preview) shows as such until then.
// `link`: a count above zero opens the event's tab that lists them.
App::uses('EventCardTool', 'Tools/EventOverview');
$event = $row['Event'] ?? [];
$counts = [
    'attributes' => ['attribute_count', '%s attribute', '%s attributes', 'attributes'],
    'objects' => ['object_count', '%s object', '%s objects', 'objects'],
    'reports' => ['report_count', '%s report', '%s reports', 'reports'],
    'correlations' => ['correlation_count', '%s correlation', '%s correlations', 'correlation'],
];
[$key, $one, $many, $tab] = $counts[$field['count']];
if (!isset($event[$key])) {
    if (!empty($field['pending'])) {
        printf('<span class="te-pending" title="%s">…</span>', h(__('Counting…')));
    }
    return;
}
$n = (int)$event[$key];
$title = $this->EventIndex->plural($n, $one, $many);
if ($key === 'attribute_count') {
    [$tab, $title] = $this->EventIndex->attributesTab($event);
}
$tag = function ($title, $html) use ($field, $event, $n, $tab) {
    if (empty($field['link']) || empty($event['id']) || !$n) {
        return sprintf('<span title="%s">%s</span>', h($title), $html);
    }
    return sprintf(
        '<a class="te-count" href="%s" title="%s">%s</a>',
        h($this->EventIndex->tabUrl($event['id'], $tab)),
        h($title),
        $html
    );
};
// Correlations and objects stop at Event::INDEX_CORRELATION_LIMIT and
// Event::INDEX_OBJECT_LIMIT.
$atLeast = [
    'correlation_count' => __('At least %s correlations', $n),
    'object_count' => __('At least %s objects', $n),
];
if (isset($atLeast[$key]) && !empty($event[$key . '_more'])) {
    echo $tag($atLeast[$key], EventCardTool::compactCount($n) . '+');
    return;
}
echo $tag(
    $title,
    $n ? EventCardTool::compactCount($n) : '<span class="te-zero">0</span>'
);
