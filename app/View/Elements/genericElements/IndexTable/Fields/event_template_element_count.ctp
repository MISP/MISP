<?php
/*
 * IndexTable field renderer for event-template complexity gauges.
 * Counts entries in $row[...]['definition']['structure'] filtered
 * by the `count_type` option:
 *
 *   'section'      — number of section elements (visual groupings)
 *   'non_section'  — number of non-section elements (every interactive
 *                    field + text blocks + object references)
 *
 * Used twice on the event-templates index — one column per filter —
 * to give operators a quick read of template complexity.
 */
// Direct array access — Hash::extract behaves oddly when the value
// at the path is itself a nested array of objects.
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
