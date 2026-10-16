<?php
/**
 * How the score was reached, as a rail card.
 *
 * Beside the ledger rather than under it: this is the ledger's
 * arithmetic, and an analyst checking whether a signal was
 * double-counted wants the sum in view while reading the rows.
 *
 * Earned and deducted points share one scale, so the strip and the
 * legend are read against the same ruler, and the deduction is hatched
 * in the colour of the group it came out of rather than recoloured.
 *
 * @var array $valueIntelligence
 */
$verdict = $valueIntelligence['verdict'];
$composition = $verdict['composition'] ?? array();

$positive = 0;
$negative = 0;
foreach ($composition as $segment) {
    if ($segment['points'] >= 0) {
        $positive += $segment['points'];
    } else {
        $negative += abs($segment['points']);
    }
}
$span = max($positive + $negative, 1);
?>
<?php if (!empty($composition)): ?>
    <div class="card shadow-sm mb-3 vp-panel vp-aside">

        <div class="vp-aside-head">
            <i class="fas fa-calculator"
               style="color: var(--enrichment);"></i>
            <span class="vp-aside-title">
                <?= h($verdict['signal_strength'] === null
                    ? __('How the signal strength was reached')
                    : sprintf(
                        __('How %s was reached'),
                        $verdict['signal_strength']
                    )) ?>
            </span>
        </div>

        <div class="p-3">

            <div class="vp-composition"
                 title="<?= h(sprintf(
                     __('%1$s points earned, %2$s deducted, %3$s net'),
                     $positive,
                     $negative,
                     $positive - $negative
                 )) ?>">
                <?php foreach ($composition as $segment):
                    if ($segment['points'] < 0) {
                        continue;
                    }
                    ?>
                    <span class="vp-composition-seg"
                          style="width: <?= round(
                              $segment['points'] / $span * 100,
                              2
                          ) ?>%; --vp-seg-color: <?=
                              h($segment['colour']) ?>;"
                          title="<?= h(sprintf(
                              '%1$s +%2$s',
                              $segment['label'],
                              $segment['points']
                          )) ?>"></span>
                <?php endforeach; ?>
                <?php if ($negative > 0): ?>
                    <span class="vp-composition-cut"
                          style="width: <?= round(
                              $negative / $span * 100,
                              2
                          ) ?>%;"
                          title="<?= h(sprintf(
                              __('%s points deducted'),
                              $negative
                          )) ?>"></span>
                <?php endif; ?>
            </div>

            <div class="vp-comp-legend">
                <?php foreach ($composition as $segment):
                    $points = (int)$segment['points'];
                    ?>
                    <div class="vp-comp-row">
                        <span class="vp-comp-swatch"
                              style="--vp-seg-color: <?=
                                  h($segment['colour']) ?>;"></span>
                        <span class="vp-comp-name">
                            <?= h($segment['label']) ?>
                        </span>
                        <span class="vp-comp-pts<?= $points < 0
                            ? ' vp-comp-pts-down'
                            : '' ?>">
                            <?= h(($points > 0 ? '+' : '') . $points) ?>
                        </span>
                    </div>
                <?php endforeach; ?>
                <div class="vp-comp-row vp-comp-total">
                    <span class="vp-comp-name"><?= __('Total') ?></span>
                    <span class="vp-comp-pts">
                        <?= h($positive - $negative) ?> / 100
                    </span>
                </div>
            </div>

            <?php if (!empty($verdict['composition_note'])): ?>
                <p class="vp-comp-note">
                    <?= h($verdict['composition_note']) ?>
                </p>
            <?php endif; ?>

        </div>

    </div>
<?php endif; ?>
