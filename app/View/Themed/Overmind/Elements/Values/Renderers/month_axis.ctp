<?php
/**
 * The time axis under a strip of month bars that share its width equally:
 * every month under its bar while there are a dozen or fewer, each year
 * under its own months, and a tick where a year begins. Past a dozen only
 * the years are named, those with most of their months drawn, thinned so
 * that they never run into each other.
 *
 * @var string[] $months `Y-m`, ascending, one per bar
 */
$months = array_values($months);
$n = count($months);
if ($n < 2) {
    return;
}
$centre = function ($from, $span) use ($n) {
    return round(($from + $span / 2) / $n * 100, 3);
};
$years = array();
foreach ($months as $i => $month) {
    $year = substr($month, 0, 4);
    if (!isset($years[$year])) {
        $years[$year] = array('from' => $i, 'span' => 0);
    }
    $years[$year]['span']++;
}
$named = $n <= 12;
// A year is 12 / $n of the width; keep each label at least 7% apart.
$every = $named ? 1 : max(1, (int)ceil(0.07 * $n / 12));
?>
<div class="vp-rf-axis<?= $named ? ' vp-rf-axis-named' : '' ?>"
     aria-hidden="true">
    <?php foreach ($years as $year => $span): ?>
        <?php if ($span['from'] > 0): ?>
            <span class="vp-rf-axis-tick" style="left: <?=
                round($span['from'] / $n * 100, 3) ?>%"></span>
        <?php endif; ?>
    <?php endforeach; ?>
    <?php if ($named): ?>
        <?php foreach ($months as $i => $month): ?>
            <span class="vp-rf-axis-m" style="left: <?=
                $centre($i, 1) ?>%"><?=
                h(date('M', strtotime($month . '-01'))) ?></span>
        <?php endforeach; ?>
    <?php endif; ?>
    <?php foreach ($years as $year => $span): ?>
        <?php if ($named
            || ($span['span'] >= 6 && (int)$year % $every === 0)
        ): ?>
            <span class="vp-rf-axis-y" style="left: <?=
                $centre($span['from'], $span['span']) ?>%"><?=
                h($year) ?></span>
        <?php endif; ?>
    <?php endforeach; ?>
</div>
