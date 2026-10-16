<?php
/**
 * One tab of a galaxy's full matrix, for the matrix modal: the tabs holding
 * techniques found up front, the rest under "More".
 *
 * @var array $matrix EventMatrixTool::full(), plus origins
 * @var string $lightIcon the glyph marking the weaker state
 */
$origins = $matrix['origins'];
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
$cell = function (array $item, array $extra = []) use (&$cellData, $origins) {
    $index = count($cellData);
    $foreign = empty($item['foreign']) ? [] : array_values(array_filter($item['origins'], function ($id) use ($origins) {
        return isset($origins[$id]);
    }));
    $cellData[] = $extra + [
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
$button = function (array $item, $state, $index) use ($lightIcon) {
    $ind = $state === 'indicators';
    return sprintf(
        '<button type="button" class="mx-cell" data-matrix-cell data-state="%s" data-i="%d" aria-label="%s"><span class="mx-name">%s</span><span class="mx-meta"><span class="mx-tid">%s%s</span></span></button>',
        h($state), $index, h(trim($item['label'] . ' ' . $item['tid'])), h($item['label']),
        $ind ? '<i class="' . h($lightIcon) . '" aria-hidden="true"></i>' : '',
        h($item['tid'])
    );
};
?>
<div class="mx-full" data-mx-full-galaxy="<?= (int)$matrix['galaxy']['id'] ?>" data-mx-tab="<?= h($current) ?>">
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
