<?php
/*
 * BS5 IndexTable field renderer for event-template complexity gauges.
 * Mirrors app/View/Elements/genericElements/IndexTable/Fields/event_template_element_count.ctp
 * for the Overmind theme. Same `count_type` semantics: 'section' counts
 * section elements, anything else (default 'non_section') counts the
 * complement.
 */
$structure = isset($row['EventTemplate']['definition']['structure'])
    ? $row['EventTemplate']['definition']['structure']
    : array();
if (!is_array($structure)) {
    $structure = array();
}
$mode = isset($field['count_type']) ? (string)$field['count_type'] : 'non_section';
$count = 0;
foreach ($structure as $el) {
    if (!is_array($el) || empty($el['type'])) {
        continue;
    }
    if ($mode === 'section') {
        if ($el['type'] === 'section') {
            $count++;
        }
    } else {
        if ($el['type'] !== 'section') {
            $count++;
        }
    }
}
echo (int)$count;
?>
