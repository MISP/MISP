<?php
// Overmind collections index: one count (`count`: members, graphs), as the events index draws one.
$collection = $row['Collection'] ?? [];
$counts = [
    'members' => ['element_count', '%s member', '%s members'],
    'graphs' => ['graph_count', '%s saved graph', '%s saved graphs'],
];
[$key, $one, $many] = $counts[$field['count']];
if (!isset($collection[$key])) {
    return;
}
$n = (int)$collection[$key];
// A card has no column heading: the count says what it counts
if (isset($viewMode) && $viewMode === 'card') {
    printf('<span class="ci-tally%s">%s</span>', $n ? '' : ' te-zero', h(__n($one, $many, $n, number_format($n))));
    return;
}
printf(
    '<span title="%s">%s</span>',
    h(__n($one, $many, $n, $n)),
    $n ? h(number_format($n)) : '<span class="te-zero">0</span>'
);
