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
$styles = array(
    'section' => array(
        'colour' => '#8B5CF6',
        'icon' => 'fas fa-folder-tree',
        'title' => __('Sections in this template'),
    ),
    'non_section' => array(
        'colour' => '#0D9488',
        'icon' => 'fas fa-puzzle-piece',
        'title' => __('Fields in this template'),
    ),
);
$style = isset($styles[$mode]) ? $styles[$mode] : $styles['non_section'];

// Zero reads as "nothing here" rather than as a value worth colouring
$background = $count === 0 ? 'var(--bs-secondary)' : $style['colour'];
?>
<span class="badge rounded-pill px-3 py-2 shadow-sm"
      style="background-color:<?= h($background) ?>; color:#fff;"
      title="<?= h($style['title']) ?>">
    <i class="<?= h($style['icon']) ?> me-1"></i><?= (int)$count ?>
</span>
