<?php
/**
 * The add control as entries of a menu a record has already: Add to
 * workspace (In workspace ✓ once the workspace holds it, then Remove from
 * workspace), Add to another collection…, New collection with this….
 * intel-graph-actions.js runs them.
 *
 * @var array $items The records, as IntelGraph.add() takes them, each with a label
 * @var string $itemClass Classes of each entry (default 'dropdown-item')
 * @var string $iconClass Classes added to each glyph (default '')
 * @var bool $wrap Each entry in its own <li> (default false)
 */
$itemClass = $itemClass ?? 'dropdown-item';
$iconClass = isset($iconClass) && $iconClass !== '' ? ' ' . $iconClass : '';
$wrap = !empty($wrap);
$json = json_encode(array_values($items));
$several = count($items) > 1;
// Font Awesome glyphs at a fixed width, as the menus they join draw theirs
$glyphClass = function ($icon) use ($iconClass) {
    return $icon . (strpos($icon, 'fa-') !== false ? ' fa-fw' : '') . $iconClass;
};
$entries = [
    [
        'attr' => 'data-intel-graph-add',
        'icon' => 'text-analystGraph misp-icon misp-icon-analyst-graph misp-simple',
        'label' => __('Add to workspace'),
        'extra' => [
            'data-intel-graph-label-in' => __('In workspace ✓ — show in the dock'),
            'data-intel-graph-icon-in' => $glyphClass('text-success fas fa-check'),
        ],
    ],
    [
        'attr' => 'data-intel-graph-remove',
        'icon' => 'fas fa-folder-minus',
        'label' => __('Remove from workspace'),
        'class' => 'ig-add-item-danger',
        'extra' => ['data-intel-graph-when' => 'in', 'hidden' => 'hidden'],
    ],
    [
        'attr' => 'data-intel-graph-other',
        'icon' => 'fas fa-folder-plus',
        'label' => __('Add to another collection…'),
    ],
    [
        'attr' => 'data-intel-graph-new',
        'icon' => 'fas fa-circle-plus',
        'label' => $several ? __('New collection with these…') : __('New collection with this…'),
    ],
];
foreach ($entries as $entry):
    $attrs = array_merge([
        'class' => trim($itemClass . ' ' . ($entry['class'] ?? '')),
        'href' => '#',
        $entry['attr'] => $json,
    ], $entry['extra'] ?? []);
    $html = '';
    foreach ($attrs as $name => $value) {
        $html .= sprintf(' %s="%s"', h($name), h($value));
    }
    $glyph = sprintf('<i class="%s"%s aria-hidden="true"></i>', h($glyphClass($entry['icon'])), $entry['attr'] === 'data-intel-graph-add' ? ' data-intel-graph-icon' : '');
?>
<?= $wrap ? '<li>' : '' ?><a<?= $html ?>><?= $glyph ?> <span class="ig-add-lbl"><?= h($entry['label']) ?></span></a><?= $wrap ? '</li>' : '' ?>
<?php endforeach; ?>
