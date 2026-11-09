<?php
/**
 * A lifetime map read as bars on one time scale: a row per bucket (or
 * per type with its own lifetime), its current stretch then its aging
 * one, so a two-week bucket and a two-year one can be compared by eye.
 * The scale is logarithmic and shared by both lifetime cards
 * (`ruler.longest`); Edit shows the map's table instead.
 *
 * @var array $block A lifetime map with its `ruler`
 */
App::uses('ValueRelevanceTool', 'Tools/ValueIntelligence');

$ruler = $block['ruler'];
// The axis runs a little past the longest lifetime, so its bar ends inside the track.
$top = max(14, (int)ceil($ruler['longest'] * 1.3));
$at = function ($days) use ($top) {
    return round(log(max(1, $days)) / log($top) * 100, 2);
};
$ticks = array();
foreach (array(
    7 => __('1 week'),
    30 => __('1 month'),
    90 => __('3 months'),
    365 => __('1 year'),
    730 => __('2 years'),
    1825 => __('5 years'),
    3650 => __('10 years'),
) as $days => $word) {
    if ($days < $top) {
        $ticks[] = array('at' => $at($days), 'word' => $word);
    }
}
// A round reading of the days, said only where it is exact.
$human = function ($days) {
    if ($days >= 365 && $days % 365 === 0) {
        return sprintf(__n('%s year', '%s years', $days / 365), $days / 365);
    }
    if ($days >= 30 && $days % 30 === 0) {
        return sprintf(__n('%s month', '%s months', $days / 30), $days / 30);
    }
    if ($days >= 7 && $days % 7 === 0) {
        return sprintf(__n('%s week', '%s weeks', $days / 7), $days / 7);
    }
    return null;
};

$byType = ($block['value_type'] ?? null) === 'types';
$rows = array();
foreach ($block['entries'] as $entry) {
    if (!empty($entry['key_field'])) {
        $field = $entry['key_field'];
        $days = (int)($field['value'] === null ? $field['default'] : $field['value']);
    } else {
        $days = (int)$entry['value'];
    }
    $days = max(1, $days);
    $agingDay = ValueRelevanceTool::agingDay($ruler['aging'], $ruler['speed'], $days);
    $rows[] = array(
        'entry' => $entry,
        'days' => $days,
        'human' => $human($days),
        'aging' => $agingDay,
        'cur' => $agingDay > 0 ? $at($agingDay) : 0,
        'end' => $at($days),
        'was' => isset($entry['replaces']) ? $at($entry['replaces']['days']) : null,
    );
}
?>
<div class="ap-life">
    <?php if (empty($rows)): ?>
        <div class="wb-empty">
            <span class="wb-empty-h"><?= h($block['empty_label'] ?? '') ?></span>
            <span><?= h($block['empty_note'] ?? '') ?></span>
        </div>
    <?php else: ?>
        <div class="ap-life-row ap-life-head" aria-hidden="true">
            <span><?= h($block['key_label']) ?></span>
            <span class="ap-life-scale">
                <?php foreach ($ticks as $tick): ?>
                    <span style="--at: <?= h($tick['at']) ?>%"><?= h($tick['word']) ?></span>
                <?php endforeach; ?>
            </span>
            <span><?= h($byType ? $block['value_label'] : __('Instead of')) ?></span>
        </div>
        <ul class="ap-life-rows">
            <?php foreach ($rows as $row): ?>
                <?php $entry = $row['entry']; ?>
                <li class="ap-life-row<?= isset($entry['note']) ? ' is-default' : '' ?>">
                    <div class="ap-life-name">
                        <b class="<?= $byType ? '' : 'wb-id' ?>"><?= h($entry['label'] ?? $entry['key']) ?></b>
                        <span class="ap-life-days">
                            <?= h(sprintf(__n('%s day', '%s days', $row['days']), $row['days'])) ?>
                            <?php if ($row['human'] !== null): ?>
                                <span>· <?= h($row['human']) ?></span>
                            <?php endif; ?>
                        </span>
                        <span class="ap-life-aging"><?= h(sprintf(__('aging from day %s'), $row['aging'])) ?></span>
                    </div>
                    <div class="ap-life-track" role="img" aria-label="<?= h(sprintf(
                        __('Current until day %1$s, aging until day %2$s, then expired.'),
                        $row['aging'], $row['days'])) ?>">
                        <?php foreach ($ticks as $tick): ?>
                            <i class="ap-life-grid" style="left: <?= h($tick['at']) ?>%"></i>
                        <?php endforeach; ?>
                        <span class="ap-life-cur" style="width: <?= h($row['cur']) ?>%"></span>
                        <span class="ap-life-age" style="left: <?= h($row['cur']) ?>%; width: <?=
                            h(max(0, $row['end'] - $row['cur'])) ?>%"></span>
                        <?php if ($row['was'] !== null): ?>
                            <span class="ap-life-was" style="left: <?= h($row['was']) ?>%"
                                  title="<?= h(sprintf(__('Its bucket: %s days'), $entry['replaces']['days'])) ?>"></span>
                        <?php endif; ?>
                    </div>
                    <div class="ap-life-types">
                        <?php if ($byType && isset($entry['note'])): ?>
                            <span class="wb-sub"><?= h($entry['note']) ?></span>
                        <?php elseif ($byType): ?>
                            <?php if (empty($entry['value'])): ?>
                                <span class="wb-sub"><?= h(__('nothing assigned')) ?></span>
                            <?php else: ?>
                                <?php foreach ($entry['value'] as $type): ?>
                                    <span class="chip is-on"><?= h($type) ?></span>
                                <?php endforeach; ?>
                            <?php endif; ?>
                        <?php elseif (isset($entry['replaces'])): ?>
                            <span class="ap-life-instead">
                                <?= h(sprintf(__n('%s day', '%s days', $entry['replaces']['days']),
                                    $entry['replaces']['days'])) ?>
                                <span class="wb-sub">· <?= h($entry['replaces']['label']) ?></span>
                            </span>
                        <?php endif; ?>
                    </div>
                </li>
            <?php endforeach; ?>
        </ul>
        <p class="ap-life-key">
            <span><i class="ap-life-sw is-cur" aria-hidden="true"></i><?= h(__('current')) ?></span>
            <span><i class="ap-life-sw is-age" aria-hidden="true"></i><?= h(__('aging, still inside its lifetime')) ?></span>
            <?php if (!$byType): ?>
                <span><i class="ap-life-sw is-was" aria-hidden="true"></i><?= h(__('what its bucket would give it')) ?></span>
            <?php endif; ?>
            <span><?= h(__('then expired')) ?></span>
        </p>
    <?php endif; ?>
</div>
