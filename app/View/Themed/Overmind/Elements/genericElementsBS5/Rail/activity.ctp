<?php
/**
 * Activity body: the total and the last time, a strip of bars per day or
 * month, and the card's stats.
 */
$rc = $this->RailCard;
$series = $card['series'];
$bucket = $card['bucket'] === 'month' ? 'month' : 'day';
$n = count($series);
$max = max(array_column($series, 'count'));
$unit = 10;
$height = 56;
$gap = $bucket === 'month' ? 2 : 2.5;
$marks = [];
$bars = '';
foreach ($series as $i => $point) {
    $ts = strtotime($point['start']);
    $firstOfMonth = date('j', $ts) === '1';
    if ($bucket === 'day' && $firstOfMonth) {
        if ($i > 0) {
            $bars .= sprintf('<rect class="rcard-strip-tick" x="%s" y="0" width="1" height="%d"></rect>', $i * $unit - 0.5, $height);
        }
        $marks[] = ['left' => $i / $n * 100, 'label' => date('M', $ts)];
    }
    $barHeight = $point['count'] ? max(3, $point['count'] / $max * ($height - 4)) : 2;
    $bars .= sprintf(
        '<rect class="%s" x="%s" y="%s" width="%s" height="%s"><title>%s</title></rect>',
        $point['count'] ? 'rcard-strip-bar' : 'rcard-strip-zero',
        $i * $unit + $gap / 2,
        round($height - $barHeight, 2),
        $unit - $gap,
        round($barHeight, 2),
        h(($bucket === 'month' ? date('M Y', $ts) : $point['start']) . ': ' . number_format($point['count']))
    );
}
?>
<div class="rcard-lede">
    <?= $rc->figure($card['total']['count'], $card['total']['label']) ?>
    <?= $rc->last($card['last']) ?>
</div>
<div class="rcard-strip rcard-strip-<?= $bucket ?>">
    <svg class="rcard-strip-svg" viewBox="0 0 <?= $n * $unit ?> <?= $height ?>" preserveAspectRatio="none" role="img"
        aria-label="<?= h($card['title']) ?>"><?= $bars ?></svg>
    <?php if ($bucket === 'month'): ?>
        <div class="rcard-axis rcard-axis-grid" style="grid-template-columns: repeat(<?= $n ?>, minmax(0, 1fr));">
            <?php foreach ($series as $point): ?>
                <?php $ts = strtotime($point['start']); ?>
                <span title="<?= h(date('M Y', $ts)) ?>"><?= h(substr(date('M', $ts), 0, 1)) ?></span>
            <?php endforeach; ?>
        </div>
    <?php else: ?>
        <div class="rcard-axis">
            <?php foreach ($marks as $mark): ?>
                <?php if ($mark['left'] <= 90): ?>
                    <span class="rcard-axis-mark" style="left: <?= round($mark['left'], 2) ?>%;"><?= h($mark['label']) ?></span>
                <?php endif; ?>
            <?php endforeach; ?>
        </div>
    <?php endif; ?>
</div>
<?php if (!empty($card['stats'])): ?>
    <dl class="rcard-stats">
        <?php foreach ($card['stats'] as $stat): ?>
            <div class="rcard-stat">
                <dd class="rcard-stat-value"><?= $rc->num($stat['value']) ?></dd>
                <dt class="rcard-stat-label"><?= h($stat['label']) ?></dt>
            </div>
        <?php endforeach; ?>
    </dl>
<?php endif; ?>
