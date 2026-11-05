<?php
/**
 * The figures above the values index, in the events index's stat cards:
 * standing facts about the instance and the reader's organisation, each
 * with its longer explanation on hover. A card that leads somewhere is a
 * link.
 *
 * **New values carries its sparkline**: one bar per day for thirty days,
 * the seven the figure counts darker, today in full ink, a day from before
 * the first count a faint baseline. **Enabled warninglists**, because that
 * is the set a value is matched against. **The enrichment cache is your
 * organisation's**: a count and a window only, since a list of what an
 * organisation recently enriched is a list of what it is investigating.
 *
 * @var array $tiles As `ValueIntelligence::forTiles()`
 */
App::uses('ValueDictionaryStatsTool', 'Tools/ValueIntelligence');

$dictionary = $tiles['dictionary'];
$over = $tiles['overCorrelating'];
$warninglists = (int)$tiles['warninglists'];
$store = $tiles['store'];
$hours = (int)$store['max_age_hours'];
$floor = '≥&#8239;';
$number = function ($n) {
    return h(number_format($n, 0, '.', ' '));
};

$cards = [];
if ($dictionary === null && $tiles['dictionaryPending']) {
    $cards[] = [
        'label' => __('Distinct values'),
        'figure' => h(__('Counting…')),
        'quiet' => true,
        'title' => __('The first count runs in the background and shows here once it is done.'),
    ];
}
if ($dictionary !== null) {
    $cards[] = [
        'label' => __('Distinct values'),
        'figure' => ($dictionary['total_floor'] ? $floor : '') . $number($dictionary['total']),
        'title' => __('Each value is stored once, however many attributes carry it.'),
    ];
    $recent = $dictionary['recent'];
    if ($recent['since'] === null) {
        $window = __('last 7 days');
    } elseif (gmdate('Y-m-d', $recent['since']) === gmdate('Y-m-d')) {
        $window = __('today');
    } else {
        $window = __('since %s', gmdate('j M', $recent['since']));
    }
    if ($recent['values'] > 0) {
        $title = __n('From %s attribute added.', 'From %s attributes added.',
            $recent['attributes'], number_format($recent['attributes']));
    } elseif ($recent['attributes'] > 0) {
        $title = __n('%s attribute added, carrying a value already stored.',
            '%s attributes added, all carrying values already stored.',
            $recent['attributes'], number_format($recent['attributes']));
    } else {
        $title = __('No attributes added.');
    }
    $series = $dictionary['series'];
    $peak = max(1, max(array_map(function (array $day) {
        return (int)$day['values'];
    }, $series)));
    $windowFrom = count($series) - ValueDictionaryStatsTool::WINDOW_DAYS;
    $bars = '';
    foreach ($series as $i => $day) {
        $label = gmdate('j M', strtotime($day['day'] . ' UTC'));
        if ($day['values'] === null) {
            $class = 'vi-spark__bar vi-spark__bar--uncounted';
            $barTitle = __('%s: not counted yet', $label);
            $height = 0;
        } else {
            $class = 'vi-spark__bar';
            if ($i === count($series) - 1) {
                $class .= ' vi-spark__bar--today';
            } elseif ($i >= $windowFrom) {
                $class .= ' vi-spark__bar--window';
            }
            $barTitle = __n('%s: %s new value', '%s: %s new values', $day['values'],
                $label, number_format($day['values']));
            $height = round(100 * $day['values'] / $peak, 1);
        }
        $bars .= '<i class="' . $class . '" style="--h: ' . h($height) . '%" title="' . h($barTitle) . '"></i>';
    }
    $cards[] = [
        'label' => __('New values') . ' · ' . $window,
        'figure' => $recent['values'] > 0
            ? ($recent['floor'] ? $floor : '') . '+' . $number($recent['values'])
            : h(__('None')),
        'quiet' => $recent['values'] === 0,
        'title' => $title,
        'extra' => '<span class="vi-spark" aria-hidden="true">' . $bars . '</span>',
        'class' => 'vi-stat-new',
    ];
}
if ($over !== null) {
    $cards[] = [
        'label' => __('Too common to correlate'),
        'figure' => $over['count'] > 0 ? $number($over['count']) : h(__('None')),
        'quiet' => $over['count'] === 0,
        'title' => __('Values matching more than %s attributes are no longer correlated.',
            number_format($over['limit'])),
        'url' => $over['review'] && $over['count'] > 0 ? $this->Html->url([
            'controller' => 'correlations',
            'action' => 'overCorrelations',
        ]) : null,
    ];
}
$cards[] = [
    'label' => __('Warninglists'),
    'figure' => $warninglists > 0
        ? h(__('%s enabled', number_format($warninglists)))
        : h(__('None enabled')),
    'amber' => $warninglists === 0,
    'title' => $warninglists > 0
        ? __('Every value is checked against the enabled warninglists.')
        : __('No value will be flagged as a known false positive.'),
    'url' => !empty($isSiteAdmin) ? $this->Html->url([
        'controller' => 'warninglists',
        'action' => 'index',
    ]) : null,
];
$cards[] = [
    'label' => __('Enrichment cache') . ' · ' . __n('%s hour', '%s hours', $hours, number_format($hours)),
    'figure' => $store['count'] > 0 ? $number($store['count']) : h(__('None yet')),
    'quiet' => $store['count'] === 0,
    'title' => __n(
        'Results cached for your organisation. Each is kept %s hour before a module is queried again.',
        'Results cached for your organisation. Each is kept %s hours before a module is queried again.',
        $hours,
        number_format($hours)
    ),
];
?>
<div class="ifp-stats vi-stats" role="group" aria-label="<?= h(__('Figures for this instance')) ?>">
    <?php foreach ($cards as $card): ?>
        <?php
        $class = trim('ifp-stat ' . ($card['class'] ?? '') . (!empty($card['amber']) ? ' is-amber' : '')
            . (!empty($card['quiet']) ? ' is-quiet' : ''));
        $body = '<span class="ifp-stat-label">' . h($card['label'])
            . (!empty($card['url']) ? '<i class="fas fa-arrow-right ifp-stat-act" aria-hidden="true"></i>' : '')
            . '</span><span class="vi-stat-row"><span class="ifp-stat-fig">' . $card['figure'] . '</span>'
            . ($card['extra'] ?? '') . '</span>';
        ?>
        <?php if (!empty($card['url'])): ?>
            <a class="<?= h($class) ?>" href="<?= h($card['url']) ?>" title="<?= h($card['title']) ?>"><?= $body ?></a>
        <?php else: ?>
            <div class="<?= h($class) ?>" title="<?= h($card['title']) ?>"><?= $body ?></div>
        <?php endif; ?>
    <?php endforeach; ?>
</div>
