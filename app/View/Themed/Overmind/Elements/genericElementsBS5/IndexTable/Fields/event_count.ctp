<?php
// Overmind events index: one count (`count`: attributes, objects, reports, correlations).
App::uses('EventCardTool', 'Tools/EventOverview');
$event = $row['Event'] ?? [];
$counts = [
    'attributes' => ['attribute_count', '%s attribute', '%s attributes'],
    'objects' => ['object_count', '%s object', '%s objects'],
    'reports' => ['report_count', '%s report', '%s reports'],
    'correlations' => ['correlation_count', '%s correlation', '%s correlations'],
];
[$key, $one, $many] = $counts[$field['count']];
if (!isset($event[$key])) {
    return;
}
$n = (int)$event[$key];
// Correlations and objects stop at Event::INDEX_CORRELATION_LIMIT and
// Event::INDEX_OBJECT_LIMIT.
$atLeast = [
    'correlation_count' => __('At least %s correlations', $n),
    'object_count' => __('At least %s objects', $n),
];
if (isset($atLeast[$key]) && !empty($event[$key . '_more'])) {
    printf(
        '<span title="%s">%s+</span>',
        h($atLeast[$key]),
        EventCardTool::compactCount($n)
    );
    return;
}
printf(
    '<span title="%s">%s</span>',
    h($this->EventIndex->plural($n, $one, $many)),
    $n ? EventCardTool::compactCount($n) : '<span class="te-zero">0</span>'
);
