<?php
/**
 * One tab of a galaxy's full matrix, for the matrix modal: the tabs holding
 * techniques found up front, the rest under "More".
 *
 * @var array $matrix EventMatrixTool::full(), plus origins
 * @var string $lightIcon the glyph marking the weaker state
 * @var bool $heat optional: shade the used techniques by how many events carry them
 * @var array $marks optional: cluster tag name => self|similar, ringed and kept out of the heat
 * @var bool $counts optional: print the event count in the used cells
 */
$origins = $matrix['origins'];
$marks = $marks ?? [];
$markOf = function (array $item) use ($marks) {
    return $marks[$item['cluster']['tag_name'] ?? ''] ?? null;
};
$eventsOf = function (array $item) use ($markOf) {
    $events = $markOf($item) ? 0 : (int)($item['events'] ?? 0);
    if (!empty($item['own']) && !$markOf($item['own'])) {
        $events = max($events, (int)($item['own']['events'] ?? 0));
    }
    foreach ($item['subs'] ?? [] as $sub) {
        if (!$markOf($sub)) {
            $events = max($events, (int)($sub['events'] ?? 0));
        }
    }
    return $events;
};
$maxEvents = 0;
if (!empty($heat)) {
    foreach ($matrix['columns'] as $column) {
        foreach ($column['groups'] as $group) {
            $maxEvents = max($maxEvents, $eventsOf($group));
        }
    }
}
$active = array_values(array_filter($matrix['tabs'], function ($tab) {
    return $tab['active'] > 0;
}));
$others = array_values(array_filter($matrix['tabs'], function ($tab) {
    return $tab['active'] === 0;
}));
if (empty($active)) {
    $active = array_slice($matrix['tabs'], 0, 1);
    $others = array_slice($matrix['tabs'], 1);
}
$current = $matrix['tab'];
$inMore = !in_array($current, array_column($active, 'key'), true);

$cellData = [];
$cell = function (array $item, array $extra = []) use (&$cellData, $origins, $markOf) {
    $index = count($cellData);
    $foreign = empty($item['foreign']) ? [] : array_values(array_filter($item['origins'], function ($id) use ($origins) {
        return isset($origins[$id]);
    }));
    if (isset($item['cluster']) && $markOf($item)) {
        $extra['m'] = $markOf($item);
    }
    $cellData[] = $extra + ($item['extra'] ?? []) + [
        'l' => $item['label'],
        't' => $item['tid'],
        'c' => $item['cluster']['id'] ?? null,
        'g' => $item['state'] === 'idle' ? null : ($item['cluster']['tag_name'] ?? null),
        'e' => !empty($item['onEvent']),
        'k' => (int)($item['events'] ?? 0),
        'n' => (int)($item['indicators'] ?? 0),
        'o' => (int)($item['loose'] ?? 0),
        'f' => $foreign,
    ];
    return $index;
};
$showCounts = !empty($counts);
$button = function (array $item, $state, $index) use ($lightIcon, $eventsOf, $maxEvents, $markOf, $showCounts) {
    $ind = $state === 'indicators';
    $mark = isset($item['cluster']) ? $markOf($item) : (isset($item['own']['cluster']) ? $markOf($item['own']) : null);
    $shade = '';
    if ($maxEvents > 0 && $state === 'event' && !$mark) {
        $shade = sprintf(' style="--mx-heat:%d%%"', 12 + round(48 * log(1 + $eventsOf($item)) / log(1 + $maxEvents)));
    }
    $meta = '<span class="mx-tid">' . ($ind ? '<i class="' . h($lightIcon) . '" aria-hidden="true"></i>' : '') . h($item['tid']) . '</span>';
    if ($showCounts && $state === 'event') {
        $events = (int)($item['events'] ?? 0);
        foreach ($item['subs'] ?? [] as $sub) {
            $events = max($events, (int)($sub['events'] ?? 0));
        }
        $meta .= '<span class="mx-k">' . (int)max($events, (int)($item['own']['events'] ?? 0)) . '</span>';
    } elseif ($state === 'declared') {
        $meta .= '<i class="fas fa-link mx-li" aria-hidden="true"></i>';
    }
    $here = '';
    if ($mark === 'self') {
        $here = '<span class="mx-here" title="' . h(__('This cluster')) . '"><i class="fas fa-location-crosshairs" aria-hidden="true"></i></span>';
    } elseif ($mark === 'similar') {
        $here = '<span class="mx-here is-similar" title="' . h(__('Similar to this cluster')) . '"><i class="fas fa-equals" aria-hidden="true"></i></span>';
    }
    return sprintf(
        '<button type="button" class="mx-cell%s" data-matrix-cell data-state="%s" data-i="%d"%s aria-label="%s">%s<span class="mx-name">%s</span><span class="mx-meta">%s</span></button>',
        $mark ? ' mx-mark-' . h($mark) : '',
        h($state), $index, $shade, h(trim($item['label'] . ' ' . $item['tid'])), $here, h($item['label']), $meta
    );
};
?>
<div class="mx-full" data-mx-full-galaxy="<?= (int)$matrix['galaxy']['id'] ?>" data-mx-tab="<?= h($current) ?>"<?= $maxEvents > 0 ? ' data-mx-heat' : '' ?>>
    <div class="mx-full-tabs" role="tablist" aria-label="<?= h(__('Matrix tabs')) ?>">
        <?php foreach ($active as $tab): ?>
        <button type="button" class="mx-full-tab" role="tab" data-mx-tab-pick="<?= h($tab['key']) ?>"
                aria-selected="<?= $tab['key'] === $current ? 'true' : 'false' ?>">
            <?= h($tab['label']) ?>
            <?php if ($tab['active'] > 0): ?><span class="badge rounded-pill"><?= (int)$tab['active'] ?></span><?php endif; ?>
        </button>
        <?php endforeach; ?>
        <?php if (!empty($others)): ?>
        <div class="dropdown mx-full-more">
            <button type="button" class="mx-full-tab dropdown-toggle" data-bs-toggle="dropdown" aria-expanded="false"
                    aria-selected="<?= $inMore ? 'true' : 'false' ?>">
                <?= h($inMore ? $matrix['tabs'][array_search($current, array_column($matrix['tabs'], 'key'), true)]['label'] : __('More')) ?>
            </button>
            <ul class="dropdown-menu">
                <?php foreach ($others as $tab): ?>
                <li><button type="button" class="dropdown-item<?= $tab['key'] === $current ? ' active' : '' ?>" data-mx-tab-pick="<?= h($tab['key']) ?>"><?= h($tab['label']) ?></button></li>
                <?php endforeach; ?>
            </ul>
        </div>
        <?php endif; ?>
    </div>
    <div class="mx-full-scroll">
        <?php if (empty($matrix['columns'])): ?>
        <div class="mx-full-empty"><?= __('This tab has no techniques.') ?></div>
        <?php else: ?>
        <?php if (max(array_column($matrix['columns'], 'active')) === 0): ?>
        <div class="mx-full-empty mx-full-none"><?= __('No technique of this tab is used.') ?></div>
        <?php endif; ?>
        <div class="mx-full-grid">
            <?php foreach ($matrix['columns'] as $column): ?>
            <section class="mx-col<?= $column['active'] > 0 ? '' : ' is-unused' ?>">
                <div class="mx-col-h" title="<?= h($column['label']) ?>">
                    <span><?= h($column['label']) ?></span>
                    <span class="mx-col-n"><?= $column['active'] > 0 ? (int)$column['active'] . ' / ' : '' ?><?= count($column['groups']) ?></span>
                </div>
                <?php foreach ($column['groups'] as $group): ?>
                <?php
                $subs = $group['subs'];
                $facts = $group['own'] ?? ['label' => $group['label'], 'tid' => $group['tid'], 'state' => $group['state']];
                $extra = ['u' => count($subs)];
                $litSubs = array_filter($subs, function ($sub) {
                    return $sub['state'] !== 'idle';
                });
                if (!empty($litSubs) && ($group['own']['state'] ?? 'idle') === 'idle') {
                    $extra['w'] = array_values(array_map(function ($sub) {
                        return $sub['label'] . ' ' . $sub['tid'];
                    }, $litSubs));
                }
                if ($group['own'] === null) {
                    $extra['s'] = array_map(function ($sub) {
                        return [$sub['label'], $sub['tid'], $sub['cluster']['id']];
                    }, $subs);
                }
                $index = $cell(['label' => $group['label'], 'tid' => $group['tid']] + $facts, $extra);
                ?>
                <div class="mx-row">
                    <?php if (!empty($subs)): ?>
                    <button type="button" class="mx-fold" aria-expanded="false"
                            aria-label="<?= h(__('Show the sub-techniques of %s', $group['label'])) ?>"><i class="fas fa-chevron-right"></i></button>
                    <?php else: ?>
                    <span></span>
                    <?php endif; ?>
                    <?= $button($group, $group['state'], $index) ?>
                </div>
                <?php if (!empty($subs)): ?>
                <div class="mx-subs" hidden>
                    <?php foreach ($subs as $sub): ?>
                    <?= $button($sub, $sub['state'], $cell($sub, ['p' => $group['label']])) ?>
                    <?php endforeach; ?>
                </div>
                <?php endif; ?>
                <?php endforeach; ?>
            </section>
            <?php endforeach; ?>
        </div>
        <?php endif; ?>
    </div>
    <script type="application/json" data-mx-cells><?= json_encode($cellData, JSON_HEX_TAG | JSON_HEX_AMP) ?></script>
</div>
