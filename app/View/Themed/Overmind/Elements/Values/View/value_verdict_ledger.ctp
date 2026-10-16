<?php
/**
 * The signal ledger: every row that produced the score, and every row
 * that refused to.
 *
 * A real table rather than a stack of rows, so Signal, Evidence,
 * Contribution and As of line up down the page and a reader can scan
 * one column at a time. A signal links to the tab holding its evidence.
 *
 * Grouped by kind rather than sorted by weight: an analyst checking
 * whether the sightings were counted twice wants them next to each
 * other, not scattered through a ranking.
 *
 * **Every row here weighs the record**, since
 * `review-2026-09-13.md` §D1: ▲ is a row where the record carries
 * something — corroboration, publication, attribution, a datable
 * observation — and ▼ one where it does not. The direction no longer
 * depends on the lean, which is the point: *four organisations
 * reported it* is the same fact about the record whether the record
 * concluded threat or benign, and anchoring it used to render that
 * fact as `−28` **against** a benign reading.
 *
 * The rows that do read the value — the warninglist's hits and
 * false-positive sightings — are not in this table. They are in the
 * lean band above, which is the surface that explains the reading, and
 * keeping them out is what lets this table sum to the signal strength exactly.
 *
 * Contradictions are a group inside this table rather than a card of
 * their own: they are ledger rows whose contribution is `unresolved`,
 * and lifting them out would imply they had been netted off somewhere.
 *
 * @var array $verdict
 */
App::uses('ValueBandReasonTool', 'Tools/ValueIntelligence');

$ledger = $verdict['ledger'] ?? array();
$conflicts = $verdict['conflicts'] ?? array();

/*
 * Contribution is drawn as a bar against the heaviest signal as well as
 * printed: the ledger is read for shape — which signals carry the
 * verdict — and a column of signed integers alone hides that behind
 * arithmetic.
 */
$heaviest = 1;
foreach ($ledger as $group) {
    foreach ($group['signals'] as $signal) {
        $heaviest = max($heaviest, abs((int)$signal['contribution']));
    }
}
?>
<div class="vp-ledger-head"
     title="<?= h(__('What the record is worth, whatever it says about'
         . ' the value. These rows sum to the signal strength.')) ?>">
    <i class="fas fa-list-check vp-ledger-head-mark"></i>
    <?= h(__('Signal strength')) ?>
    <span class="vp-vc-axis-head-sub">
        <?= h(__('how the score was built')) ?>
    </span>
    <?php if (isset($verdict['signal_strength'])): ?>
        <span class="vp-vc-axis-head-total">
            <?= h((int)$verdict['signal_strength']) ?> / 100
        </span>
    <?php endif; ?>
</div>
<?php if (empty($ledger) && empty($conflicts)): ?>
    <div class="vp-empty">
        <i class="fas fa-list-check"></i>
        <span><?= __('No signal contributed to this assessment.') ?></span>
    </div>
<?php else: ?>
    <div class="table-responsive">
        <table class="table table-sm mb-0 vp-ledger-table">
            <thead>
                <tr>
                    <th class="vp-ledger-dir"></th>
                    <th><?= __('Signal') ?></th>
                    <th><?= __('Evidence') ?></th>
                    <th class="vp-ledger-contrib-col"
                        title="<?= h(__(
                            'Points toward the signal strength. A row'
                            . ' adds where the record has something and'
                            . ' deducts where it lacks it, whichever'
                            . ' way the value leans.'
                        )) ?>">
                        <?= __('Contribution') ?>
                    </th>
                    <th class="vp-ledger-asof-col">
                        <?= __('As of') ?>
                    </th>
                </tr>
            </thead>
            <tbody>

                <?php foreach ($ledger as $group): ?>
                    <tr class="vp-ledger-group">
                        <td colspan="5">
                            <?= h($group['kind']) ?>
                            <?php if (!empty($group['note'])): ?>
                                <span class="vp-ledger-group-note">
                                    <?= h($group['note']) ?>
                                </span>
                            <?php endif; ?>
                        </td>
                    </tr>
                    <?php foreach ($group['signals'] as $signal):
                        $up = $signal['direction'] === 'up';
                        $points = abs((int)$signal['contribution']);
                        ?>
                        <tr class="vp-ledger-line<?= $up
                            ? ' vp-ledger-line-up'
                            : ' vp-ledger-line-down' ?>">
                            <td class="vp-ledger-dir">
                                <?= $up ? '&#9650;' : '&#9660;' ?>
                            </td>
                            <td class="vp-ledger-signal-cell">
                                <?php if (empty($signal['tab'])): ?>
                                    <?= h($signal['signal']) ?>
                                <?php else: ?>
                                    <a class="vp-ledger-signal-link"
                                       href="#tab-<?= h($signal['tab']) ?>"
                                       title="<?= h(__(
                                           'Open the tab holding this'
                                           . ' evidence'
                                       )) ?>">
                                        <?= h($signal['signal']) ?>
                                    </a>
                                <?php endif; ?>
                            </td>
                            <td class="vp-ledger-evidence">
                                <?= h($signal['evidence']) ?>
                            </td>
                            <td>
                                <div class="vp-ledger-contrib-cell"
                                     title="<?= h(sprintf(
                                         __('%s points'),
                                         $signal['contribution']
                                     )) ?>">
                                    <span class="vp-vc-bar">
                                        <span class="vp-vc-bar-fill"
                                              style="width: <?= round(
                                                  $points / $heaviest
                                                  * 100,
                                                  2
                                              ) ?>%;"></span>
                                    </span>
                                    <span class="vp-ledger-points">
                                        <?= h(
                                            ($signal['contribution'] > 0
                                                ? '+'
                                                : '')
                                            . $signal['contribution']
                                        ) ?>
                                    </span>
                                </div>
                            </td>
                            <td class="vp-ledger-asof">
                                <?= h($signal['as_of']) ?>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                <?php endforeach; ?>

                <?php
                /*
                 * Contradictions, in the same table and marked
                 * `unresolved`. Not netted off, and not moved
                 * somewhere that would imply they had been.
                 */
                ?>
                <?php if (!empty($conflicts)): ?>
                    <tr class="vp-ledger-group vp-ledger-group-conflict">
                        <td colspan="5">
                            <?= __('Contradictions') ?>
                            <span class="vp-ledger-group-note">
                                <?= __(
                                    'where the record disagrees with'
                                    . ' itself; no points'
                                ) ?>
                            </span>
                        </td>
                    </tr>
                    <?php foreach ($conflicts as $conflict): ?>
                        <tr class="vp-ledger-conflict">
                            <td class="vp-ledger-dir">
                                <span class="vp-ledger-mark">
                                    &#9670;
                                </span>
                            </td>
                            <td class="vp-ledger-signal-cell">
                                <?= h($conflict['title']) ?>
                            </td>
                            <td class="vp-ledger-evidence">
                                <?= h($conflict['evidence']
                                    ?? $conflict['note']) ?>
                            </td>
                            <td>
                                <span class="vp-ledger-unresolved">
                                    <?= __('no points') ?>
                                </span>
                            </td>
                            <td class="vp-ledger-asof">
                                <?= h(__('now')) ?>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                <?php endif; ?>

            </tbody>
        </table>
    </div>

    <?php
    /*
     * The band, under the arithmetic that produced it.
     *
     * A foot rather than a band of its own, which is the difference
     * between this axis and the other two: relevance and lean needed
     * somewhere to show their working and got `vp-vc-clock` and
     * `vp-vc-lean`, while signal strength's working is the table directly
     * above. What it never said is where the boundary is — `low`
     * against a `medium` floor of 30 — or, twice over, that the points
     * are not what decided the band at all. That sentence belongs
     * against the rows it is about, not in a fifth band.
     *
     * `10-wiring.md` §19.
     */
    ?>
    <?php $bandReason = ValueBandReasonTool::reasonFor($verdict); ?>
    <?php if ($bandReason !== null): ?>
        <div class="vp-ledger-foot">
            <i class="fas fa-ruler-horizontal"></i>
            <span><?= h($bandReason) ?></span>
        </div>
    <?php endif; ?>
<?php endif; ?>
