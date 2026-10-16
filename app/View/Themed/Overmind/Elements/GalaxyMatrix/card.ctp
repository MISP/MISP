<?php
/**
 * A galaxy matrix rail card: per matrix galaxy, its tactics stacked with the
 * techniques found, in a strong state (`event`) and a weaker one
 * (`indicators`). Nothing at all when there is none and the roll-up has run.
 *
 * @var array $matrix galaxies, origins and rolledUp, EventMatrixTool::compact()
 * @var array $texts the states' wording: onEvent, onlyOne/Many, onOne/Many,
 *            and showOne/Many when the weaker state can be listed
 * @var string $fullUrl one galaxy's full matrix, %s standing for its id
 * @var string|null $rollupUrl where the weaker state is counted on demand
 * @var string $lightIcon the glyph marking the weaker state
 */
$galaxies = $matrix['galaxies'];
$origins = $matrix['origins'];
$rolledUp = $matrix['rolledUp'];
if (empty($galaxies) && $rolledUp) {
    return;
}
$rollupUrl = $rollupUrl ?? null;
$tile = '--tile:var(--bs-galaxy);--tile-bg:color-mix(in srgb, var(--bs-galaxy) 18%, transparent);';

$texts += [
    'subOf' => __('Sub-technique of %s'),
    'throughOne' => __('Through 1 sub-technique'),
    'throughMany' => __('Through %s sub-techniques'),
    'open' => __('Open the technique'),
    'openSub' => __('Open %s'),
    'close' => __('Close'),
    'tickOne' => __('1 technique'),
    'tickMany' => __('%s techniques'),
    'failed' => __('Could not load the matrix.'),
];

$badge = function ($originId) use ($origins) {
    $origin = $origins[$originId] ?? null;
    if ($origin === null) {
        return '';
    }
    $palette = $origin['palette'];
    return sprintf(
        '<span class="badge mx-badge d-inline-flex align-items-center gap-1" style="background:%s;color:%s;border:1px solid %s"><i class="fas %s"></i><span>#%d</span></span>',
        h($palette['badgeBg']), h($palette['badgeText']), h($palette['badgeBorder']),
        $origin['role'] === 'extended' ? 'fa-code-merge' : 'fa-code-branch',
        (int)$originId
    );
};

$foreignOrigins = function (array $item) use ($origins) {
    if (empty($item['foreign'])) {
        return [];
    }
    return array_values(array_filter($item['origins'], function ($id) use ($origins) {
        return isset($origins[$id]);
    }));
};

$cellData = [];
$cell = function (array $item, $state, array $facts, array $extra = []) use (&$cellData, $badge, $foreignOrigins, $lightIcon) {
    $index = count($cellData);
    $foreign = $foreignOrigins($facts);
    $cellData[] = $extra + [
        'l' => $item['label'],
        't' => $item['tid'],
        'c' => $facts['cluster']['id'] ?? null,
        'g' => $facts['cluster']['tag_name'] ?? null,
        'e' => !empty($facts['onEvent']),
        'n' => (int)($facts['indicators'] ?? 0),
        'o' => (int)($facts['loose'] ?? 0),
        'f' => $foreign,
    ];
    $ind = $state === 'indicators';
    $meta = '';
    if ($item['tid'] !== '' || $ind) {
        $meta .= '<span class="mx-tid">'
            . ($ind ? '<i class="' . h($lightIcon) . '" aria-hidden="true"></i>' : '')
            . h($item['tid']) . '</span>';
    }
    $meta .= implode('', array_map($badge, $foreign));
    return sprintf(
        '<button type="button" class="mx-cell" data-matrix-cell data-state="%s" data-i="%d" aria-haspopup="dialog" aria-label="%s"><span class="mx-name">%s</span><span class="mx-meta">%s</span></button>',
        h($state), $index, h(trim($item['label'] . ' ' . $item['tid'])), h($item['label']), $meta
    );
};

$subLine = function (array $galaxy) use ($rolledUp) {
    $techniques = __n('%s technique', '%s techniques', $galaxy['techniques'], $galaxy['techniques']);
    if (!$rolledUp) {
        return __('%s on the event', $techniques);
    }
    return $techniques . ' · ' . __n('%s tactic', '%s tactics', count($galaxy['tactics']), count($galaxy['tactics']));
};
?>
<?php if (empty($galaxies)): ?>
<div class="card shadow-sm mb-3 mx-card mx-card--line" data-matrix-card data-mx-text="<?= h(json_encode($texts)) ?>">
    <div class="mx-line" title="<?= h(__('No matrix technique on the event itself; the indicators\' techniques are not counted yet')) ?>">
        <div class="misp-icon-tile rounded-2 d-flex align-items-center justify-content-center" style="width:28px;height:28px;<?= $tile ?>">
            <i class="fas fa-table-cells" style="font-size:.8rem;"></i>
        </div>
        <div class="mx-line-txt">
            <b><?= __('Matrix') ?></b>
            <button type="button" class="mx-include" data-mx-rollup="<?= h($rollupUrl) ?>"><?= __('Include the indicators\' techniques') ?></button>
        </div>
    </div>
</div>
<?php return; endif; ?>
<?php
$many = count($galaxies) > 1;
$first = $galaxies[0];
$title = $many
    ? __n('%s matrix galaxy', '%s matrix galaxies', count($galaxies), count($galaxies))
    : $first['name'];
?>
<div class="card shadow-sm mb-3 mx-card" data-matrix-card
     data-mx-full-url="<?= h($fullUrl) ?>"
     data-mx-text="<?= h(json_encode($texts)) ?>">
    <div class="mx-head d-flex align-items-center gap-2">
        <div class="misp-icon-tile rounded-2 d-flex align-items-center justify-content-center" style="width:36px;height:36px;<?= $tile ?>">
            <i class="fas fa-<?= h($first['icon'] ?: 'map') ?>" style="font-size:1rem;" data-mx-icon></i>
        </div>
        <div class="me-auto" style="min-width:0">
            <div class="fw-bold lh-1 mx-title"><?= h($title) ?></div>
            <div class="small text-muted mt-1" data-mx-sub><?= h($subLine($first)) ?></div>
        </div>
        <button type="button" class="btn btn-sm btn-outline-secondary mx-full-open" data-matrix-full
                title="<?= h(__('Open the full matrix')) ?>" aria-label="<?= h(__('Open the full matrix')) ?>">
            <i class="fas fa-expand"></i>
        </button>
    </div>
    <?php if ($many): ?>
    <div class="mx-switch" role="group" aria-label="<?= h(__('Galaxy')) ?>">
        <?php foreach ($galaxies as $i => $galaxy): ?>
        <button type="button" class="mx-switch-opt" data-mx-galaxy-pick="<?= (int)$galaxy['id'] ?>"
                aria-pressed="<?= $i === 0 ? 'true' : 'false' ?>" title="<?= h($galaxy['name']) ?>">
            <i class="fas fa-<?= h($galaxy['icon'] ?: 'map') ?>" aria-hidden="true"></i>
            <span class="mx-switch-name"><?= h($galaxy['name']) ?></span>
            <span class="mx-switch-n"><?= (int)$galaxy['techniques'] ?></span>
        </button>
        <?php endforeach; ?>
    </div>
    <?php endif; ?>
    <?php foreach ($galaxies as $i => $galaxy): ?>
    <div class="mx-galaxy" data-mx-galaxy="<?= (int)$galaxy['id'] ?>" data-mx-name="<?= h($galaxy['name']) ?>"
         data-mx-icon-name="<?= h($galaxy['icon'] ?: 'map') ?>" data-mx-sub-text="<?= h($subLine($galaxy)) ?>"<?= $i === 0 ? '' : ' hidden' ?>>
        <div class="mx-strip" role="navigation" aria-label="<?= h(__('Jump to a tactic')) ?>" hidden>
            <?php foreach ($galaxy['tactics'] as $t => $tactic): ?>
            <?php $tacticOnEvent = in_array('event', array_column($tactic['groups'], 'state'), true); ?>
            <button type="button" class="mx-tick" data-t="<?= $t ?>" data-n="<?= count($tactic['groups']) ?>"
                    data-state="<?= $tacticOnEvent ? 'event' : 'indicators' ?>" style="--n:<?= count($tactic['groups']) ?>"
                    aria-label="<?= h($tactic['label']) ?>"></button>
            <?php endforeach; ?>
        </div>
        <div class="mx-pane-wrap">
            <div class="mx-pane">
                <?php foreach ($galaxy['tactics'] as $t => $tactic): ?>
                <section class="mx-tactic" data-t="<?= $t ?>">
                    <div class="mx-tactic-h"><span><?= h($tactic['label']) ?></span><span class="mx-tactic-n"><?= count($tactic['groups']) ?></span></div>
                    <div class="mx-cells">
                        <?php foreach ($tactic['groups'] as $group): ?>
                        <?php
                        $subs = $group['subs'];
                        $extra = ['u' => count($subs)];
                        if ($group['own'] === null) {
                            $extra['s'] = array_map(function ($sub) {
                                return [$sub['label'], $sub['tid'], $sub['cluster']['id']];
                            }, $subs);
                        }
                        ?>
                        <div class="mx-row">
                            <?php if (!empty($subs)): ?>
                            <button type="button" class="mx-fold" aria-expanded="false"
                                    aria-label="<?= h(__('Show the sub-techniques of %s', $group['label'])) ?>"><i class="fas fa-chevron-right"></i></button>
                            <?php else: ?>
                            <span></span>
                            <?php endif; ?>
                            <?= $cell($group, $group['state'], $group['own'] ?? $group, $extra) ?>
                        </div>
                        <?php if (!empty($subs)): ?>
                        <div class="mx-subs" hidden>
                            <?php foreach ($subs as $sub): ?>
                            <?= $cell($sub, $sub['state'], $sub, ['p' => $group['label']]) ?>
                            <?php endforeach; ?>
                        </div>
                        <?php endif; ?>
                        <?php endforeach; ?>
                    </div>
                </section>
                <?php endforeach; ?>
            </div>
        </div>
    </div>
    <?php endforeach; ?>
    <script type="application/json" data-mx-cells><?= json_encode($cellData, JSON_HEX_TAG | JSON_HEX_AMP) ?></script>
    <?php if (!$rolledUp): ?>
    <div class="mx-gate">
        <span><?= __('The indicators\' techniques are not counted yet.') ?></span>
        <button type="button" class="mx-include" data-mx-rollup="<?= h($rollupUrl) ?>"><?= __('Include the indicators\' techniques') ?></button>
    </div>
    <?php endif; ?>
</div>
