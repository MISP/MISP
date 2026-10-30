<?php
/**
 * A profile's sections in the detail-page frame, for the view and the
 * editor alike: one tab per family, each section a card the reader folds,
 * the document in its own tab, and a rail every tab shares.
 *
 * @var bool $editable
 * @var array $rail Element paths, see view_layout's `rail`
 * @var array $profile
 * @var array $sections
 * @var array $groups
 * @var array $bench
 * @var string|null $value
 * @var string|null $open_section
 * @var array|null $standing This profile's row of the index board
 */
App::uses('AnalystProfileFormTool', 'Tools/AnalystProfile');

$readings = AnalystProfileFormTool::benchReadings($bench['detail']);
// A benched value is read against the signals first.
$opened = $open_section !== null
    ? $open_section
    : ($value === null ? null : 'signals');

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
    return (string)$n;
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
    'assessment' => 'fas fa-clipboard-check',
    'behaviour' => 'fas fa-sliders',
    'display' => 'fas fa-eye',
);
// The editor fills a tab's badge when a section in it has unsaved changes.
$unsaved = $editable ? array('deferred' => true) : null;
$tabs = array();
foreach ($groups as $key => $label) {
    if (empty($grouped[$key])) {
        continue;
    }
    $cards = array();
    $first = true;
    foreach ($grouped[$key] as $id => $section) {
        $pill = $count($section);
        if ($id === 'signals' && $standing !== null) {
            $pill = sprintf(__('%s of %s on'), $standing['signals']['enabled'],
                $standing['signals']['configured']);
        }
        $cards[] = array(
            'element' => 'AnalystProfiles/view_section',
            'params' => array(
                'section' => $section,
                'editable' => $editable,
                'open' => $first || $opened === $id,
                'count' => $pill,
                'readings' => $readings,
                'benchValue' => $value,
            ),
        );
        $first = false;
    }
    $tabs[] = array(
        'id' => $key,
        'title' => $label,
        'icon' => isset($icons[$key]) ? $icons[$key] : 'fas fa-list',
        'count' => count($grouped[$key]),
        'badge' => $unsaved,
        'active' => $opened !== null && isset($grouped[$key][$opened]),
        'left' => $cards,
    );
}
$tabs[] = array(
    'id' => 'document',
    'title' => __('Document'),
    'icon' => 'fas fa-code',
    'badge' => $unsaved,
    'active' => $opened === 'raw',
    'left' => array(array(
        'element' => 'AnalystProfiles/view_raw',
        'params' => array('editable' => $editable, 'open' => $opened === 'raw'),
    )),
);
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
    'tabs' => $tabs,
    'rail' => $rail,
)) ?>
