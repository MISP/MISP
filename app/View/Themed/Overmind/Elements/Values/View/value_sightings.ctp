<?php
/**
 * Who has seen this value, and when.
 *
 * MISP has three sighting types and they mean opposite things: a
 * sighting supports the value, a false positive contradicts it, an
 * expiration retires it. They are shown apart, never summed into one
 * "activity" number.
 *
 * Lazily loaded into `.ajax-card` from ValuesController::viewSightings.
 *
 * @var array $valueIntelligence
 * @var string $valueB64
 */
$sightings = $valueIntelligence['sightings'];
$positive = $sightings['total'] - $sightings['fp'] - $sightings['expiration'];
$spark = $sightings['spark'];
$reporters = $sightings['reporters'];
$topReporter = empty($reporters) ? 0 : $reporters[0]['count'];

/*
 * ------------------------------------------------------------------
 * The strip is signed, and the two halves share one unit
 * ------------------------------------------------------------------
 * Support grows up from the line, contradiction hangs below it — the
 * geometry `sightingSeries` gives the tab's own chart, so a reader who
 * has learned it there reads this the same way. It counted type 0 and
 * dropped the other two entirely until 2026-09-14, which put 47 reports
 * on the strip and 6 nowhere, directly under two tiles counting exactly
 * those 6.
 *
 * **The halves are sized in proportion to their own peaks**, which is
 * what makes one unit one height on both sides. Split 50/50 instead and
 * a column holding one false positive would out-draw a column holding
 * five sightings — a worse claim than the omission this replaces. A
 * value nobody has contradicted gets the whole strip for its support
 * and draws exactly as it did before.
 */
$peakUp = 0;
$peakDown = 0;
foreach ($spark as $column) {
    $peakUp = max($peakUp, $column['sighting']);
    $peakDown = max($peakDown, $column['fp'] + $column['expiration']);
}
$scale = $peakUp + $peakDown;
$upShare = $scale > 0 ? 100 * $peakUp / $scale : 100;

$noWrites = __(
    'Disabled in this pass — the Value Intelligence page does not write to'
    . ' the database yet.'
);

$subtitle = $sightings['total'] === 0
    ? h(__('Never sighted'))
    : h(sprintf(__('Last sighting %s'), $sightings['last']));
?>
<div class="card shadow-sm mb-3 vp-panel"
     style="--vp-panel-color: var(--sighting);">

    <?= $this->element('Values/View/value_panel_header', array(
        'panelTitle' => __('Sightings'),
        'panelIcon' => 'misp-icon misp-icon-sighting misp-simple',
        'panelColor' => 'var(--sighting)',
        'panelSub' => $subtitle,
    )) ?>

    <div class="p-3 d-flex flex-column gap-3">

        <div class="vp-stat-row">
            <div class="vp-stat vp-stat-primary">
                <div class="vp-stat-value"><?= h($positive) ?></div>
                <div class="vp-stat-label"><?= __('Sightings') ?></div>
            </div>
            <div class="vp-stat<?= $sightings['fp'] > 0
                ? ' vp-stat-fp'
                : '' ?>">
                <div class="vp-stat-value"><?= h($sightings['fp']) ?></div>
                <div class="vp-stat-label"><?= __('False positive') ?></div>
            </div>
            <div class="vp-stat<?= $sightings['expiration'] > 0
                ? ' vp-stat-exp'
                : '' ?>">
                <div class="vp-stat-value">
                    <?= h($sightings['expiration']) ?>
                </div>
                <div class="vp-stat-label"><?= __('Expiration') ?></div>
            </div>
        </div>

        <?php if (!empty($spark)): ?>
            <div>
                <div class="vp-spark vp-spark-signed" role="img"
                     style="--vp-spark-up: <?= round($upShare, 2) ?>%;"
                     aria-label="<?= h($peakDown > 0
                         ? __(
                             'Reports over the last 90 days — sightings'
                             . ' above the line, false positives and'
                             . ' expirations below it'
                         )
                         : __('Sightings over the last 90 days')
                     ) ?>">
                    <?php foreach ($spark as $column):
                        $down = $column['fp'] + $column['expiration'];
                        /*
                         * Both halves divide by the *same* scale, not
                         * by their own peak, which is what the split
                         * above buys: `--vp-spark-up` gives the top
                         * region exactly its share of the height, so a
                         * percentage of that region is the same number
                         * of pixels per report as a percentage of the
                         * bottom one.
                         */
                        $pct = function ($n, $peak) {
                            return $peak > 0
                                ? round(100 * $n / $peak, 2)
                                : 0;
                        };
                        ?>
                        <span class="vp-spark-col" title="<?= h(sprintf(
                            __('%1$s — %2$s'),
                            $column['from'] === $column['to']
                                ? $column['from']
                                : sprintf(
                                    __('%1$s to %2$s'),
                                    $column['from'],
                                    $column['to']
                                ),
                            implode(', ', array(
                                sprintf(__n(
                                    '%s sighting',
                                    '%s sightings',
                                    $column['sighting']
                                ), $column['sighting']),
                                sprintf(__n(
                                    '%s false positive',
                                    '%s false positives',
                                    $column['fp']
                                ), $column['fp']),
                                sprintf(__n(
                                    '%s expiration',
                                    '%s expirations',
                                    $column['expiration']
                                ), $column['expiration']),
                            ))
                        )) ?>">
                            <span class="vp-spark-up">
                                <span class="vp-spark-seg vp-spark-seg-yes"
                                      style="height: <?=
                                          $pct($column['sighting'], $peakUp)
                                      ?>%;"></span>
                            </span>
                            <?php
                            /*
                             * No region at all where nothing
                             * contradicts the value, rather than one of
                             * zero height: it carries the axis rule on
                             * its top edge, and a 1px border inside a
                             * 0px box is 1px the fixed-height strip does
                             * not have. A value nobody has contradicted
                             * then draws exactly what it drew before
                             * this was a signed chart.
                             */
                            ?>
                            <?php if ($peakDown > 0): ?>
                                <span class="vp-spark-down">
                                    <span class="vp-spark-seg
                                                 vp-spark-seg-fp"
                                          style="height: <?=
                                              $pct($column['fp'], $peakDown)
                                          ?>%;"></span>
                                    <span class="vp-spark-seg
                                                 vp-spark-seg-exp"
                                          style="height: <?=
                                              $pct(
                                                  $column['expiration'],
                                                  $peakDown
                                              )
                                          ?>%;"></span>
                                </span>
                            <?php endif; ?>
                        </span>
                    <?php endforeach; ?>
                </div>
                <div class="vp-spark-axis">
                    <span><?= __('90 days ago') ?></span>
                    <span><?= __('today') ?></span>
                </div>
            </div>
        <?php endif; ?>

        <?php if (!empty($reporters)): ?>
            <div>
                <?php
                /*
                 * **The subhead names the unit, which it did not.** The
                 * bars count every report an organisation filed and the
                 * tile two inches above says *47 Sightings*, so
                 * *Reported by* over bars summing to 53 was a column a
                 * reader could not reconcile with the number it sat
                 * under. The Reporters card on the tab has always said
                 * *reports*; this one says it too, and the bars are
                 * split by what those reports said.
                 */
                ?>
                <div class="vp-subhead">
                    <?= h(sprintf(
                        __n(
                            'Reported by — %s report',
                            'Reported by — %s reports',
                            $sightings['total']
                        ),
                        number_format($sightings['total'])
                    )) ?>
                </div>
                <?= $this->element('Values/View/value_sighting_bars', array(
                    'bars' => $reporters,
                    'barsTop' => $topReporter,
                )) ?>
            </div>
        <?php else: ?>
            <div class="vp-empty vp-empty-inline">
                <span class="misp-icon misp-icon-sighting misp-simple"></span>
                <span><?= __('Nobody has reported seeing this.') ?></span>
            </div>
        <?php endif; ?>

        <button type="button"
                class="btn btn-sm btn-outline-secondary w-100
                       d-flex align-items-center justify-content-center gap-1"
                disabled
                title="<?= h($noWrites) ?>">
            <span class="misp-icon misp-icon-sighting misp-simple"></span>
            <?= __('I saw this') ?>
        </button>

    </div>

</div>
