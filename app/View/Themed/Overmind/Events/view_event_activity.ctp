<?php
App::uses('ValueStatsTool', 'Tools/ValueIntelligence');

$grainWords = [
    'day' => __('one bar a day'),
    'week' => __('one bar a week'),
    'month' => __('one bar a month'),
];
$lastChange = (int)($event['Event']['timestamp'] ?? 0);
?>
<div class="row g-4">
    <div class="col-12 col-md-6">
        <div class="eo-band-label"><?= __('First recorded change') ?></div>
        <div><?= $first === null ? '<span class="eo-muted">' . __('No attribute or object yet') . '</span>' : $this->Time->time($first) ?></div>
    </div>
    <div class="col-12 col-md-6">
        <div class="eo-band-label"><?= __('Last change') ?></div>
        <div><?= $lastChange ? $this->Time->time($lastChange) : '<span class="eo-muted">' . __('Unknown') . '</span>' ?></div>
    </div>
    <?php if ($histogram !== null): ?>
        <?php $bars = $histogram['bars']; ?>
        <div class="col-12">
            <div class="eo-band-label mb-1"><?= __('Modification map') ?></div>
            <div class="eo-spark" role="img" aria-label="<?= h(__('Attribute and object changes, %s', $grainWords[$histogram['unit']])) ?>">
                <?php foreach ($bars as $bar): ?>
                    <span class="eo-spark-bar<?= $bar['count'] === 0 ? ' is-empty' : '' ?>"
                          style="--eo-spark-h: <?= $histogram['max'] > 0 ? round($bar['count'] / $histogram['max'] * 100) : 0 ?>%"
                          title="<?= h(__n('%s: %s change', '%s: %s changes', $bar['count'], $bar['label'], number_format($bar['count']))) ?>"></span>
                <?php endforeach; ?>
            </div>
            <?php $scale = ValueStatsTool::timeScale($histogram); ?>
            <?php if (!empty($scale)): ?>
                <div class="eo-spark-scale" aria-hidden="true">
                    <?php foreach ($bars as $at => $bar): ?>
                        <span class="eo-spark-slot<?= array_key_exists($at, $scale) ? ' is-tick' : '' ?>"><?php
                            if (!empty($scale[$at])): ?><span class="eo-spark-tick"><?= h($scale[$at]) ?></span><?php endif;
                        ?></span>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>
            <div class="small eo-muted mt-1">
                <?= h(__('%1$s · %2$s to %3$s', $grainWords[$histogram['unit']], $bars[0]['from'], end($bars)['to'])) ?>
            </div>
        </div>
    <?php endif; ?>
</div>
