<?php
/**
 * Who reported this value, one bar an organisation, split by what each
 * of its reports said.
 *
 * Shared by the Overview's sightings card and the Sightings tab's
 * Reporters rail, which drew the same bars from the same array in two
 * copies of the same markup — and would have needed the split made
 * twice.
 *
 * **The bar's length is every report the organisation filed, of any
 * type**, which is the rule the Reporters card has always stated: a
 * contradiction is participation, and hiding a false positive here
 * would make the most sceptical organisation look like the quietest.
 * **The bar's colours are what those reports said.** Drawn in one
 * colour it asserted the opposite of that rule — on `8.8.8.8`, CUDESO's
 * bar read 5 in the sighting purple where three of its five reports
 * corroborate the value and two contradict or retire it, under a tile
 * reading *47 SIGHTINGS* it could not be reconciled with.
 *
 * The three hues are `sightingSeries`' own — `--vp-sight-yes`,
 * `--vp-sight-fp`, `--vp-sight-exp` — so a segment here and a stack
 * segment on the tab's chart mean the same thing.
 *
 * @var array $bars    Reporter rows: `org`, `count`, and the three
 *                     kinds, from `ValueStatsTool::sightingTotals`
 * @var int $barsTop   The longest bar's count, the shared denominator
 */
$kinds = array(
    'sighting' => array('class' => 'vp-reporter-seg-yes',
        'label' => __('sighting'), 'plural' => __('sightings')),
    'fp' => array('class' => 'vp-reporter-seg-fp',
        'label' => __('false positive'),
        'plural' => __('false positives')),
    'expiration' => array('class' => 'vp-reporter-seg-exp',
        'label' => __('expiration'), 'plural' => __('expirations')),
);
?>
<div class="vp-reporters">
    <?php foreach ($bars as $bar): ?>
        <?php
        /*
         * The whole bar is the organisation's share of the longest
         * one, and each segment is its share of that — so the segments
         * always fill their bar exactly, whatever rounding does to any
         * one of them.
         */
        $width = $barsTop > 0
            ? round(100 * $bar['count'] / $barsTop, 2)
            : 0;
        $parts = array();
        foreach ($kinds as $kind => $meta) {
            $n = (int)($bar[$kind] ?? 0);
            if ($n > 0) {
                $parts[] = sprintf(
                    __n('%1$s %2$s', '%1$s %2$s', $n),
                    $n,
                    $n === 1 ? $meta['label'] : $meta['plural']
                );
            }
        }
        ?>
        <div class="vp-reporter">
            <span class="vp-reporter-name" title="<?= h($bar['org']) ?>">
                <?= h($bar['org']) ?>
            </span>
            <span class="vp-reporter-track">
                <span class="vp-reporter-fill"
                      style="width: <?= $width ?>%;"
                      title="<?= h(sprintf(
                          '%s — %s',
                          $bar['org'],
                          implode(', ', $parts)
                      )) ?>">
                    <?php foreach ($kinds as $kind => $meta): ?>
                        <?php $n = (int)($bar[$kind] ?? 0); ?>
                        <?php if ($n > 0): ?>
                            <span class="vp-reporter-seg <?=
                                h($meta['class']) ?>" style="width: <?=
                                round(100 * $n / $bar['count'], 2)
                            ?>%;"></span>
                        <?php endif; ?>
                    <?php endforeach; ?>
                </span>
            </span>
            <span class="vp-reporter-count">
                <?= h(number_format($bar['count'])) ?>
            </span>
        </div>
    <?php endforeach; ?>
</div>
