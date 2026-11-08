<?php
/**
 * One `picker` child of the filter bar: a button with a selection count and
 * a dropdown the bar's script builds on open (index-filters.js).
 *
 * - name     : filter name, unprefixed
 * - label    : button and chip label
 * - icon     : classes of the button's icon
 * - source   : search URL answering ?q= with [{value, label, style}]
 * - options  : fixed list instead of a source, [{value, label, style}]
 * - exclude  : whether a value can be excluded (`!value`)
 * - resolved : value => {label, style} for the values a URL may carry
 * - all_of   : whether `a&b` in the URL means all of them; the column
 *              browser then offers to switch between any of and all of
 * - hint     : line under the list
 * - separator: between values in the URL, '|' unless the index splits on '||'
 * - single   : one value at a time, applied as soon as it is picked
 * - suggest  : groups listed before anything is typed, [{label, rows, more}]
 * - sub      : a second filter one option drills into, {option, name, label,
 *              source answering with the whole list, exclude, resolved, hint};
 *              including any of its values narrows the picker to that option
 * - browser  : open as a column browser (index-filter-browser.js) instead of
 *              a list: {kind: 'tag'|'galaxy', scopes: URL, tree: URL (tags)}
 * - disabled : why the picker cannot be used yet; drawn but not openable, so
 *              the swap after another filter applies can bring it to life
 *
 * @var array $child
 * @var IndexFilterState $state
 */
$name = $child['name'];
$selectedOf = function (array $child) use ($state) {
    $raw = (string)$state->get($child['name']);
    $allOf = !empty($child['all_of']) && strpos($raw, '&') !== false && strpos($raw, '|') === false;
    $pieces = IndexFilterState::pieces($raw, $allOf ? '&' : ($child['separator'] ?? '|'));

    $known = [];
    foreach (($child['options'] ?? []) as $option) {
        $known[(string)$option['value']] = $option;
    }
    foreach (($child['resolved'] ?? []) as $value => $row) {
        $known[(string)$value] = $row;
    }
    foreach (($child['suggest'] ?? []) as $group) {
        foreach ($group['rows'] as $row) {
            $known[(string)$row['value']] = $row;
        }
    }
    $selected = [];
    foreach ($pieces as [$value, $excluded]) {
        $row = $known[$value] ?? null;
        $selected[] = [
            'value' => $value,
            'label' => $row['label'] ?? $value,
            'style' => $row['style'] ?? null,
            'note' => $row['note'] ?? null,
            'exclude' => $excluded && !empty($child['exclude']),
            'unresolved' => $row === null,
        ];
    }
    return [$selected, $allOf];
};
[$selected, $allOf] = $selectedOf($child);
$count = count($selected);

$sub = null;
if (!empty($child['sub'])) {
    [$subSelected] = $selectedOf($child['sub']);
    $sub = [
        'option' => (string)$child['sub']['option'],
        'name' => $child['sub']['name'],
        'label' => $child['sub']['label'],
        'source' => $child['sub']['source'],
        'exclude' => !empty($child['sub']['exclude']),
        'selected' => $subSelected,
        'hint' => $child['sub']['hint'] ?? null,
    ];
    $narrowed = array_filter($subSelected, function ($s) { return !$s['exclude']; });
    $count += count($subSelected);
    if ($narrowed && in_array($sub['option'], array_column($selected, 'value'), true)) {
        $count--;
    }
}

$config = [
    'name' => $name,
    'label' => $child['label'],
    'source' => $child['source'] ?? null,
    'options' => isset($child['options']) ? array_values($child['options']) : null,
    'exclude' => !empty($child['exclude']),
    'selected' => $selected,
    'allOf' => $allOf,
    'allOfMode' => !empty($child['all_of']),
    'hint' => $child['hint'] ?? null,
    'sep' => $child['separator'] ?? '|',
    'single' => !empty($child['single']),
    'suggest' => $child['suggest'] ?? null,
    'sub' => $sub,
    'browser' => $child['browser'] ?? null,
];
?>
<div class="ifp-picker flex-shrink-0" data-ifp-swap="picker-<?= h($name) ?>" data-ifp-picker="<?= h(json_encode($config, JSON_UNESCAPED_UNICODE)) ?>"<?= empty($child['disabled']) ? '' : ' title="' . h($child['disabled']) . '"' ?>>
    <button type="button" class="btn btn-sm btn-outline-secondary ifp-btn<?= $count ? ' is-set' : '' ?>" aria-expanded="false" aria-haspopup="dialog" data-tour="index-picker-<?= h($name) ?>"<?= empty($child['disabled']) ? '' : ' disabled' ?>>
        <?php if (!empty($child['icon'])): ?>
            <i class="<?= h($child['icon']) ?>" aria-hidden="true"></i>
        <?php endif; ?>
        <span class="ifp-btn-label"><?= h($child['label']) ?></span>
        <?php if ($count): ?>
            <span class="badge rounded-pill bg-primary" aria-label="<?= h(__n('%s selected', '%s selected', $count, $count)) ?>"><?= h($count) ?></span>
        <?php endif; ?>
        <i class="fas fa-chevron-down ifp-caret" aria-hidden="true"></i>
    </button>
    <div class="ifp-pop" role="dialog" tabindex="-1" aria-label="<?= h($child['label']) ?>" hidden></div>
</div>
