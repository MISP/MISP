<?php
/**
 * Values the instance had never stored before, over the last week, with a
 * bar per day for the last thirty.
 *
 * @var array $dictionary As ValueDictionaryStatsTool::summarise()
 */
App::uses('ValueDictionaryStatsTool', 'Tools/ValueIntelligence');

$recent = $dictionary['recent'];
$series = $dictionary['series'];
$peak = max(1, max(array_map(function (array $day) {
    return (int)$day['values'];
}, $series)));
$attributes = '<b>' . h(number_format($recent['attributes'])) . '</b>';
if ($recent['since'] === null) {
    $window = h(__('in the last 7 days'));
} elseif (gmdate('Y-m-d', $recent['since']) === gmdate('Y-m-d')) {
    $window = h(__('today'));
} else {
    $window = h(__('since %s', gmdate('j M', $recent['since'])));
}
$windowFrom = count($series) - ValueDictionaryStatsTool::WINDOW_DAYS;
?>
<div class="vi-tile" data-vi-tile="new-values">
    <div class="vi-tile__label"><i class="fas fa-seedling vi-tile__icon" aria-hidden="true"></i><?= h(__('New values')) ?></div>
<?php if ($recent['values'] === 0): ?>
    <div class="vi-tile__value vi-tile__value--none"><?= h(__('None')) ?></div>
    <div class="vi-tile__sub"><?php if ($recent['attributes'] === 0): ?><?= h(__('no attributes added %s.', $window)) ?><?php else: ?><?= sprintf(
        h(__n(
            '%s %s attribute added, carrying a value already stored.',
            '%s %s attributes added, all carrying values already stored.',
            $recent['attributes']
        )),
        h(ucfirst($window)) . ',',
        $attributes
    ) ?><?php endif; ?></div>
<?php else: ?>
    <div class="vi-tile__value"><?= $recent['floor'] ? '≥&#8239;' : '' ?>+<?= h(number_format($recent['values'])) ?></div>
    <div class="vi-spark" aria-hidden="true" data-vi-spark>
<?php foreach ($series as $i => $day): ?>
<?php
    $label = gmdate('j M', strtotime($day['day'] . ' UTC'));
    if ($day['values'] === null) {
        $class = 'vi-spark__bar vi-spark__bar--uncounted';
        $title = __('%s: not counted yet', $label);
        $height = 0;
    } else {
        $class = 'vi-spark__bar';
        if ($i === count($series) - 1) {
            $class .= ' vi-spark__bar--today';
        } elseif ($i >= $windowFrom) {
            $class .= ' vi-spark__bar--window';
        }
        $title = __n('%s: %s new value', '%s: %s new values', $day['values'], $label, number_format($day['values']));
        $height = round(100 * $day['values'] / $peak, 1);
    }
?>
        <i class="<?= $class ?>" style="--h: <?= h($height) ?>%" title="<?= h($title) ?>"></i>
<?php endforeach; ?>
    </div>
    <div class="vi-tile__sub"><?= sprintf(
        h(__n(
            '%s, from %s attribute added.',
            '%s, from %s attributes added.',
            $recent['attributes']
        )),
        $window,
        $attributes
    ) ?></div>
<?php endif; ?>
</div>
