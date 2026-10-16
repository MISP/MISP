<?php
/**
 * The relevance axis's magnitude: the shelf, as the value page draws
 * it.
 *
 * A track, a fill and a mark where aging begins. Coloured
 * `--bs-correlation`, which is what the shipped relevance card uses,
 * and deliberately not `--vp-dir-with` / `--vp-dir-against`: that pair
 * means *supports* and *disputes*, and a clock says neither.
 *
 * The whole thing is absent when there is no clock, which is a state
 * and not a gap — a value nothing is recorded for has no shelf life to
 * run down, and drawing an empty track would assert one.
 *
 * @var array|null $runway `ValueRelevanceTool`'s relevance array
 */
if (empty($runway) || !isset($runway['runway'])
    || $runway['runway'] === null
) {
    if (!empty($runway['note'])) {
        echo '<span class="ax-g">' . h($runway['note']) . '</span>';
    }
    return;
}
$ttlDays = isset($runway['ttl']['days']) ? (int)$runway['ttl']['days'] : null;
$ttlFrom = isset($runway['ttl']['type']) ? $runway['ttl']['type'] : null;
$left = (int)round($runway['runway'] * 100);
$aging = (int)round(
    (isset($runway['aging_fraction']) ? $runway['aging_fraction'] : 0.33) * 100
);
$clockAt = isset($runway['clock']['at']) && $runway['clock']['at']
    ? date('Y-m-d', $runway['clock']['at'])
    : null;
$assumed = (int)($runway['assumed_days'] ?? 0);
$recorded = isset($runway['recorded_days'])
    ? (int)$runway['recorded_days']
    : null;
?>
<div class="ax-runway">
    <div class="ax-track" title="<?= h(sprintf(
        __('%1$s of %2$s days used'),
        $runway['elapsed_days'],
        $ttlDays
    )) ?>">
        <span class="ax-fill" style="width:<?= max(0, min(100, $left)) ?>%"></span>
        <span class="ax-agemark" style="left:<?= max(0, min(100, $aging)) ?>%"
              title="<?= h(__('where it stops counting as current')) ?>"></span>
    </div>
    <span class="ax-runway-t">
        <?php if ($runway['runway_days'] < 0): ?>
            <b><?= h(-$runway['runway_days']) ?></b>
            <?= h(__('days over')) ?>
        <?php else: ?>
            <b><?= h($runway['runway_days']) ?></b>
            <?= h(sprintf(__('of %s days left'), $ttlDays)) ?>
        <?php endif; ?>
        <?php if ($ttlFrom !== null): ?>
            &middot; <?= h(__('lifetime from')) ?>
            <span class="wb-id"><?= h($ttlFrom) ?></span>
        <?php endif; ?>
        <?php if ($clockAt !== null): ?>
            &middot; <?= h(sprintf(__('clock last reset %s'), $clockAt)) ?>
        <?php endif; ?>
    </span>
    <?php if (!empty($runway['uncertain'])): ?>
        <?php
        /*
         * The assumption is on the bench because the box that sets it
         * is three fields away. A pane that shows the consequence and
         * hides the number producing it cannot be used to choose the
         * number — which was true of the threshold this replaced, and
         * is more true of an assumption, since an assumption has no
         * reading to fall back on.
         */
        ?>
        <span class="ax-runway-t wb-sub"
              title="<?= h(__('MISP records no creation date for an'
                  . ' attribute, so with no first-seen date there is'
                  . ' nothing to measure the real age with.')) ?>">
            <?= h($assumed > 0 && $recorded !== null
                ? sprintf(
                    __n(
                        'timeline uncertain — %1$s day on the record'
                            . ' plus %2$s assumed',
                        'timeline uncertain — %1$s days on the record'
                            . ' plus %2$s assumed',
                        $recorded
                    ),
                    $recorded,
                    $assumed
                )
                : sprintf(
                    __('timeline uncertain — %s'),
                    $runway['uncertain_note']
                )) ?>
            <?php if (!empty($runway['assumed_capped'])): ?>
                <?= h(sprintf(
                    __('(capped from %s — an assumption never expires a'
                        . ' value)'),
                    (int)$runway['assumed_setting']
                )) ?>
            <?php endif; ?>
        </span>
    <?php endif; ?>
</div>
