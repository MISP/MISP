<?php
/**
 * The signal-strength bands, drawn against what the enabled signals can
 * actually reach.
 *
 * The bound is not a setting: it is the largest positive value in each
 * enabled signal's points map, summed. Drawing the boundaries against
 * it is what makes `medium` above `high` — or a band nothing could ever
 * reach — visibly wrong rather than silently saved.
 *
 * @var array $strip `bound`, `attainable`, `bands`, `problems`, `ok`,
 *                   and in the editor `title`, `blurb` and `fields`
 * @var array|null $marks Values to mark on the strip: `now` and `was`
 * @var bool|null $editable
 */
$bound = max(1, (int)$strip['bound']);
$marks = isset($marks) ? $marks : array();

/*
 * The band list arrives high first, because that is the order the
 * engine tests it in. The strip reads low to high, like the axis
 * underneath it.
 */
$bands = array_reverse($strip['bands']);
$tone = array('low' => 'seg-low', 'medium' => 'seg-med', 'high' => 'seg-high');

$pct = function ($points) use ($bound) {
    $share = max(0, min(1, $points / $bound));
    return round($share * 100, 3);
};

/*
 * A mark is centred on its position, so one at either end hangs off
 * the strip and widens the pane. Kept just inside: the number it
 * carries says where it really is.
 */
$markAt = function ($points) use ($pct) {
    return max(2, min(98, $pct($points)));
};
$editable = !empty($editable);
?>
<?= $this->element('AnalystProfiles/block_head', array('block' => $strip)) ?>
<div class="wb-strip mb-1">
    <?php foreach ($bands as $band): ?>
        <?php
        $from = $pct($band['from']);
        $to = $pct(max($band['from'], $band['to']));
        ?>
        <div class="seg <?= h(isset($tone[$band['id']])
                ? $tone[$band['id']] : 'seg-low') ?>"
             style="left:<?= $from ?>%;width:<?= max(0, $to - $from) ?>%">
            <?= h($band['id']) ?>
        </div>
    <?php endforeach; ?>
    <?php foreach ($marks as $kind => $points): ?>
        <?php if ($points === null) { continue; } ?>
        <div class="wb-mark <?= $kind === 'was' ? 'ghost' : '' ?>"
             style="left:<?= $markAt($points) ?>%"><b><?= h($points) ?></b></div>
    <?php endforeach; ?>
</div>
<div class="wb-scale">
    <span style="flex:0 0 0">0</span>
    <?php $last = 0; ?>
    <?php foreach ($bands as $band): ?>
        <?php if ($band['from'] <= 0) { continue; } ?>
        <span style="flex:0 0 <?= max(0, $pct($band['from']) - $pct($last)) ?>%">
            <?= h($band['from']) ?>
        </span>
        <?php $last = $band['from']; ?>
    <?php endforeach; ?>
    <span style="flex:1 1 auto"><?= h(sprintf(
        __('%s reachable'), $strip['bound']
    )) ?></span>
</div>

<?php if (!empty($strip['fields'])): ?>
    <?= $this->element('AnalystProfiles/block_fields', array(
        'block' => array('fields' => $strip['fields']),
        'editable' => $editable,
    )) ?>
<?php endif; ?>

<?php foreach ($strip['problems'] as $problem): ?>
    <div class="wb-note <?= empty($problem['advisory']) ? 'bad' : 'warn' ?> mt-2">
        <?= h($problem['message']) ?>
    </div>
<?php endforeach; ?>

<?php if (empty($strip['attainable']['reliable'])): ?>
    <div class="wb-note warn mt-2">
        <?= h(sprintf(
            __n(
                'One enabled signal has no upper limit, so the score can'
                    . ' go past this mark: %s.',
                '%2$s enabled signals have no upper limit, so the score'
                    . ' can go past this mark: %1$s.',
                count($strip['attainable']['unbounded'])
            ),
            implode(', ', $strip['attainable']['unbounded']),
            count($strip['attainable']['unbounded'])
        )) ?>
    </div>
<?php endif; ?>
