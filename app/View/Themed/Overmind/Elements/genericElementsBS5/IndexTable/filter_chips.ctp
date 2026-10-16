<?php
/**
 * The active filters of a picker bar, one removable chip each.
 *
 * Picker values get a chip per value (× drops that value); anything else a
 * chip per parameter (× drops the parameter). Scope keys get none and
 * survive "Clear all".
 *
 * @var IndexFilterState $state
 * @var array $pickers name => picker child
 * @var array $chips labels: name => label; values: name => [value => label]
 *                   or callable(value) => string; scope: names
 * @var array $searchChild
 */
$labels = $chips['labels'] ?? [];
$valueLabels = $chips['values'] ?? [];
$scope = $chips['scope'] ?? [];
$searchKeys = array_filter([
    ($searchChild['mode'] ?? 'quickFilter') === 'quickFilter' ? 'quickFilter' : ($searchChild['name'] ?? null),
    $searchChild['id_field'] ?? null,
]);

$items = [];
foreach ($state->filters() as $name => $value) {
    if (in_array($name, $scope, true)) {
        continue;
    }
    if (isset($pickers[$name])) {
        $picker = $pickers[$name];
        $known = [];
        foreach (($picker['options'] ?? []) as $option) {
            $known[(string)$option['value']] = $option['label'];
        }
        foreach (($picker['resolved'] ?? []) as $v => $row) {
            $known[(string)$v] = $row['label'];
        }
        $allOf = !empty($picker['all_of']) && strpos($value, '&') !== false && strpos($value, '|') === false;
        if ($allOf) {
            $pieces = IndexFilterState::pieces($value, '&');
            $excluded = array_values(array_filter($pieces, function ($piece) {
                return $piece[1];
            }));
            $items[] = [
                'key' => $state->key($name),
                'label' => sprintf(__('%s (all of)'), $picker['label']),
                'op' => ':',
                'value' => implode(', ', array_map(function ($piece) use ($known) {
                    return $known[$piece[0]] ?? $piece[0];
                }, array_filter($pieces, function ($piece) {
                    return !$piece[1];
                }))),
                'href' => $state->url([$name => IndexFilterState::join($excluded)]),
            ];
            foreach ($pieces as $i => [$v, $isExcluded]) {
                if (!$isExcluded) {
                    continue;
                }
                $rest = $pieces;
                unset($rest[$i]);
                $items[] = [
                    'key' => $state->key($name),
                    'label' => $picker['label'],
                    'op' => ' ≠',
                    'value' => $known[$v] ?? $v,
                    'href' => $state->url([$name => IndexFilterState::join(
                        array_values($rest),
                        count($pieces) - count($excluded) > 1 ? '&' : '|'
                    )]),
                ];
            }
            continue;
        }
        $sep = $picker['separator'] ?? '|';
        $pieces = IndexFilterState::pieces($value, $sep);
        foreach ($pieces as $i => [$v, $excluded]) {
            $rest = $pieces;
            unset($rest[$i]);
            $items[] = [
                'key' => $state->key($name),
                'label' => $picker['label'],
                'op' => $excluded ? ' ≠' : ':',
                'value' => $known[$v] ?? $v,
                'href' => $state->url([$name => IndexFilterState::join(array_values($rest), $sep)]),
            ];
        }
        continue;
    }
    if (in_array($name, $searchKeys, true)) {
        $label = $name === ($searchChild['id_field'] ?? null)
            ? __('ID') : ($searchChild['chip_label'] ?? __('Search'));
    } else {
        $label = $labels[$name] ?? $name;
    }
    $map = $valueLabels[$name] ?? null;
    if (is_callable($map)) {
        $display = $map($value);
    } elseif (is_array($map)) {
        $display = implode(', ', array_map(function ($piece) use ($map) {
            [$v, $excluded] = $piece;
            return ($excluded ? '≠ ' : '') . ($map[$v] ?? $v);
        }, IndexFilterState::pieces($value)));
    } else {
        $display = $value;
    }
    $items[] = [
        'key' => $state->key($name),
        'label' => $label,
        'op' => $display === '' ? '' : ':',
        'value' => $display,
        'href' => $state->url([$name => null]),
    ];
}
?>
<div class="ifp-chips" data-ifp-swap="chips"<?= $items ? '' : ' hidden' ?>>
    <?php foreach ($items as $item): ?>
        <span class="ifp-chip" data-ifp-key="<?= h($item['key']) ?>">
            <span class="ifp-chip-label"><?= h($item['label']) ?><?php if ($item['op'] !== ''): ?><span class="ifp-chip-op"><?= h($item['op']) ?></span> <span class="ifp-chip-value"><?= h($item['value']) ?></span><?php endif; ?></span>
            <a href="<?= h($item['href']) ?>" class="ifp-chip-x" data-ifp-nav title="<?= h(__('Remove this filter')) ?>" aria-label="<?= h(sprintf(__('Remove %s'), $item['label'] . ($item['op'] !== '' ? $item['op'] . ' ' . $item['value'] : ''))) ?>"><i class="fas fa-times" aria-hidden="true"></i></a>
        </span>
    <?php endforeach; ?>
    <?php if ($items): ?>
        <a href="<?= h($state->clearUrl($scope)) ?>" class="ifp-clear" data-ifp-nav><?= __('Clear all') ?></a>
    <?php endif; ?>
</div>
