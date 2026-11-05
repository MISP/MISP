<?php
/**
 * A profile in the detail-page frame, for the view and the editor alike:
 * its notices, one tab per section in the order the groups put them, and
 * a rail every tab shares. The whole document is a modal the rail opens.
 *
 * @var bool $editable
 * @var array $rail Element paths, see view_layout's `rail`
 * @var array $profile
 * @var array $sections
 * @var array $groups
 * @var array $bench
 * @var string|null $value
 * @var string|null $open_section
 */
App::uses('AnalystProfileFormTool', 'Tools/AnalystProfile');

$readings = AnalystProfileFormTool::benchReadings($bench['detail']);

// What a section holds, as the editor's rail used to count it.
$count = function (array $section) {
    $n = 0;
    foreach ($section['blocks'] as $block) {
        if ($block['kind'] === 'items') {
            $n += count($block['items']);
        } elseif (!empty($block['fields'])) {
            $n += count($block['fields']);
        } elseif ($block['kind'] === 'map') {
            foreach ($block['entries'] as $entry) {
                $n += empty($entry['key_field']) ? 1 : 2;
            }
        }
    }
    return $n;
};

$grouped = array_fill_keys(array_keys($groups), array());
$fallback = array_key_last($grouped);
foreach ($sections as $id => $section) {
    $key = isset($section['group']) && isset($grouped[$section['group']])
        ? $section['group']
        : $fallback;
    $grouped[$key][$id] = $section;
}

$icons = array(
    'signals' => 'wave-square',
    'thresholds' => 'gauge',
    'escalations' => 'scale-balanced',
    'exclusions' => 'ban',
    'relevance' => 'clock-rotate-left',
    'reference' => 'shield-halved',
    'enrichment' => 'puzzle-piece',
    'context' => 'eye',
    'galaxies' => 'crosshairs',
);
// Sections drawn as a second card in another's tab: the rules that
// refuse to lean sit with the lean.
$joins = array('escalations' => 'thresholds');
$active = isset($joins[$open_section])
    ? $joins[$open_section]
    : $open_section;
// The editor fills a tab's badge when a section in it has unsaved changes.
$unsaved = $editable ? array('deferred' => true) : null;
$tabs = array();
foreach ($grouped as $members) {
    foreach ($members as $id => $section) {
        $card = array(
            'element' => 'AnalystProfiles/section_card',
            'params' => array(
                'section' => $section,
                'editable' => $editable,
                'readings' => $readings,
                'benchValue' => $value,
            ),
        );
        if (isset($joins[$id]) && isset($tabs[$joins[$id]])) {
            $tabs[$joins[$id]]['left'][] = $card;
            $tabs[$joins[$id]]['count'] += $count($section);
            continue;
        }
        $tabs[$id] = array(
            'id' => $id,
            'title' => $section['title'],
            'icon' => 'fas fa-'
                . (isset($icons[$id]) ? $icons[$id] : 'sliders'),
            'count' => $count($section),
            'badge' => $unsaved,
            'active' => $active === $id,
            'left' => array($card),
        );
    }
}
?>
<?php if (!empty($loader_errors) || !empty($errors) || !empty($warnings)
    || !empty($legacy)
): ?>
    <div class="container-fluid">
        <?= $this->element('AnalystProfiles/loader_errors', array(
            'loader_errors' => $loader_errors,
        )) ?>
        <?php foreach ($errors as $error): ?>
            <div class="wb-note bad mb-2"><?= h($error) ?></div>
        <?php endforeach; ?>
        <?php foreach ($warnings as $warning): ?>
            <div class="wb-note warn mb-2"><?= h($warning) ?></div>
        <?php endforeach; ?>
        <?php foreach ($legacy as $note): ?>
            <div class="wb-note mb-2">
                <b><?= h(__('Written by an older version.')) ?></b>
                <?= h($note) ?>
            </div>
        <?php endforeach; ?>
    </div>
<?php endif; ?>
<?= $this->element('genericElementsBS5/Layout/view_layout', array(
    'data' => $profile,
    'tabs' => array_values($tabs),
    'rail' => $rail,
)) ?>
<template id="ap-raw-modal"<?= $open_section === 'raw' ? ' data-ap-open' : '' ?>>
    <?= $this->element('AnalystProfiles/raw_modal', array(
        'editable' => $editable,
    )) ?>
</template>
