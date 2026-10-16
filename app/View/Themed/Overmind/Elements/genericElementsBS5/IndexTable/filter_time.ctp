<?php
/**
 * One `time` child of the filter bar: several "since" filters behind one
 * button, each a row of presets or a custom date range (index-filters.js).
 *
 * - name    : the button's own name, for `data-ifp-open`
 * - label   : button label
 * - icon    : classes of the button's icon
 * - fields  : [{name, label, aliases}], each filter it sets, unprefixed;
 *             an alias is read like the name and dropped when it is set
 * - presets : [{value, label, title}], time deltas the filters take
 *
 * A range goes in the URL as the `[from, to]` list the index reads.
 *
 * @var array $child
 * @var IndexFilterState $state
 */
$fields = [];
$count = 0;
foreach ($child['fields'] as $field) {
    $value = null;
    foreach (array_merge([$field['name']], $field['aliases'] ?? []) as $key) {
        $value = $state->getList($key) ?? $state->get($key);
        if ($value !== null) {
            break;
        }
    }
    if ($value !== null) {
        $count++;
    }
    $fields[] = [
        'name' => $field['name'],
        'label' => $field['label'],
        'aliases' => $field['aliases'] ?? [],
        'value' => $value,
    ];
}
$config = [
    'kind' => 'time',
    'name' => $child['name'],
    'label' => $child['label'],
    'fields' => $fields,
    'presets' => $child['presets'],
    'strings' => [
        'any' => __('Any'),
        'anyTitle' => __('No limit'),
        'custom' => __('Custom'),
        'customTitle' => __('Pick dates'),
        'from' => __('From'),
        'to' => __('To'),
        'hint' => __('Both rows apply together. Applies when you close the picker.'),
    ],
];
?>
<div class="ifp-picker flex-shrink-0" data-ifp-swap="picker-<?= h($child['name']) ?>" data-ifp-picker="<?= h(json_encode($config, JSON_UNESCAPED_UNICODE)) ?>">
    <button type="button" class="btn btn-sm btn-outline-secondary ifp-btn<?= $count ? ' is-set' : '' ?>" aria-expanded="false" aria-haspopup="dialog" data-tour="index-picker-<?= h($child['name']) ?>">
        <?php if (!empty($child['icon'])): ?>
            <i class="<?= h($child['icon']) ?>" aria-hidden="true"></i>
        <?php endif; ?>
        <span><?= h($child['label']) ?></span>
        <?php if ($count): ?>
            <span class="badge rounded-pill text-bg-primary" aria-label="<?= h(__n('%s set', '%s set', $count, $count)) ?>"><?= h($count) ?></span>
        <?php endif; ?>
        <i class="fas fa-chevron-down ifp-caret" aria-hidden="true"></i>
    </button>
    <div class="ifp-pop ifp-pop-time" role="dialog" tabindex="-1" aria-label="<?= h($child['label']) ?>" hidden></div>
</div>
