<?php
/**
 * The figures above the events index: the filtered result, counted by the
 * paginator's own aggregate (EventIndexStatsBehavior). A card that filters
 * is a link: pressed it drops its filter, otherwise it sets it and drops
 * the cards it would contradict.
 *
 * @var array $stats
 * @var IndexFilterState $state
 * @var bool $canPickOrgs
 */
$published = $state->get('published');
$pending = $state->get('pending');
$changed = $state->get('timestamp');
$lastLogin = (int)($stats['last_login'] ?? 0);

$cards = [
    [
        'label' => __('Events'),
        'figure' => $stats['total'],
    ],
    [
        'label' => __('Unpublished'),
        'figure' => $stats['unpublished'],
        'pressed' => $published === '0',
        'on' => ['published' => '0', 'pending' => null],
        'off' => ['published' => null],
        'title' => __('Never published, or unpublished since'),
    ],
    [
        'label' => __('Changes pending'),
        'figure' => $stats['pending'],
        'pressed' => $pending === '1',
        'on' => ['pending' => '1', 'published' => null],
        'off' => ['pending' => null],
        'amber' => $stats['pending'] > 0,
        'title' => __('Published once and changed since'),
    ],
    [
        'label' => __('Changed this week'),
        'figure' => $stats['changed_week'],
        'pressed' => $changed === '7d',
        'on' => ['timestamp' => '7d'],
        'off' => ['timestamp' => null],
        'title' => __('Changed in the last 7 days'),
    ],
];
if ($stats['since_last_visit'] !== null) {
    $cards[] = [
        'label' => __('Since your last visit'),
        'figure' => $stats['since_last_visit'],
        'pressed' => $changed === (string)$lastLogin,
        'on' => ['timestamp' => (string)$lastLogin],
        'off' => ['timestamp' => null],
        'title' => sprintf(__('Changed since your previous login, %s'), date('Y-m-d H:i', $lastLogin)),
    ];
}
$cards[] = [
    'label' => __('New this week'),
    'figure' => $stats['new_week'],
    'pressed' => $state->get('firstpublished') === '7d',
    'on' => ['firstpublished' => '7d'],
    'off' => ['firstpublished' => null],
    'title' => __('First published in the last 7 days'),
];
$cards[] = [
    'label' => __('Creator orgs'),
    'figure' => $stats['creator_orgs'],
    'open' => $canPickOrgs ? 'org' : null,
    'title' => $canPickOrgs ? __('Filter by creator organisation') : null,
];
$years = null;
if (!empty($stats['date_min'])) {
    $from = substr($stats['date_min'], 0, 4);
    $to = substr($stats['date_max'], 0, 4);
    $years = $from === $to ? $from : $from . '–' . $to;
}
$cards[] = [
    'label' => __('Event dates'),
    'figure' => $years ?? '—',
    'title' => !empty($stats['date_min']) ? $stats['date_min'] . ' – ' . $stats['date_max'] : null,
];
?>
<div class="ifp-stats" id="ifp-stats" data-ifp-swap role="group" aria-label="<?= h(__('Figures for these filters')) ?>">
    <?php foreach ($cards as $card): ?>
        <?php
        $figure = is_int($card['figure']) ? number_format($card['figure'], 0, '.', ' ') : $card['figure'];
        $class = 'ifp-stat' . (!empty($card['amber']) ? ' is-amber' : '');
        $title = !empty($card['title']) ? ' title="' . h($card['title']) . '"' : '';
        $body = '<span class="ifp-stat-label">' . h($card['label'])
            . (isset($card['on']) || !empty($card['open']) ? '<i class="fas fa-filter ifp-stat-act" aria-hidden="true"></i>' : '')
            . '</span><span class="ifp-stat-fig">' . h($figure) . '</span>';
        ?>
        <?php if (isset($card['on'])): ?>
            <a class="<?= $class ?>" href="<?= h($state->url($card['pressed'] ? $card['off'] : $card['on'])) ?>" data-ifp-nav role="button" aria-pressed="<?= $card['pressed'] ? 'true' : 'false' ?>"<?= $title ?>><?= $body ?></a>
        <?php elseif (!empty($card['open'])): ?>
            <button type="button" class="<?= $class ?>" data-ifp-open="<?= h($card['open']) ?>"<?= $title ?>><?= $body ?></button>
        <?php else: ?>
            <div class="<?= $class ?>"<?= $title ?>><?= $body ?></div>
        <?php endif; ?>
    <?php endforeach; ?>
</div>
