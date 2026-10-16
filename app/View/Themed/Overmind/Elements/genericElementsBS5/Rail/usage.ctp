<?php
/**
 * Usage body: one headline number and how it splits, as a bar and a legend.
 */
$rc = $this->RailCard;
$headline = $card['headline'];
$split = array_values(array_filter($card['split'], function ($part) {
    return $part['count'] > 0;
}));
$whole = array_sum(array_column($split, 'count'));
$paints = $rc->paints($split);
?>
<div class="rcard-lede">
    <?= $rc->figure($headline['count'], $headline['label'], $headline['context']) ?>
    <?= $rc->last($card['last']) ?>
</div>
<?php if (!empty($split)): ?>
    <?= $rc->stack($split, 'rcard-stack-xl', $paints) ?>
    <ul class="rcard-legend">
        <?php foreach ($split as $i => $part): ?>
            <li class="rcard-legend-row">
                <?= $rc->swatch($paints[$i]) ?>
                <span class="rcard-legend-label" title="<?= h($part['label']) ?>"><?= h($part['label']) ?></span>
                <span class="rcard-legend-count"><?= $rc->num($part['count']) ?></span>
                <span class="rcard-legend-pct<?= $rc->toneClass($part['tone'], 'rcard-tx-') ?>"><?= h($rc->pct($part['count'] / $whole)) ?></span>
            </li>
        <?php endforeach; ?>
    </ul>
<?php endif; ?>
