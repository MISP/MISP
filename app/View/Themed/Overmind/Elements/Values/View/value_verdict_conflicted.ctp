<?php
/**
 * The Assessment tab for a value whose record contradicts itself: the same
 * header, stance card and shelf life card as an agreeing value
 * (value_verdict.ctp), and in place of a single signal strength the two
 * cases side by side, weighed against each other, with what neither could
 * take. The rail is value_verdict_aside's contested branch.
 *
 * Lazily loaded into `.ajax-tab-content` from
 * ValuesController::viewVerdict.
 *
 * @var array $valueIntelligence
 */
App::uses('ValueLean', 'Tools/ValueIntelligence');

$verdict = $valueIntelligence['verdict'];
$tug = $verdict['tug'];
$tugTotal = max($tug['support'] + $tug['dispute'], 1);
$cases = $verdict['cases'];
$ambiguities = $verdict['ambiguities'] ?? array();
$heaviest = 1;
foreach ($cases as $case) {
    foreach ($case['rows'] as $row) {
        $heaviest = max($heaviest, (int)$row['points']);
    }
}
?>
<?= $this->element('Values/View/value_verdict_head', array('verdict' => $verdict)) ?>
<?= $this->element('Values/View/value_verdict_voices', array('verdict' => $verdict)) ?>

<div class="card shadow-sm mb-3 vp-panel vp-vc" style="--vp-panel-color: var(--vp-conflict);">
    <?= $this->element('Values/View/value_panel_header', array(
        'panelTitle' => __('The two cases'),
        'panelIcon' => 'fas fa-scale-unbalanced',
        'panelColor' => 'var(--vp-conflict)',
        'panelSub' => h(sprintf(
            __('Threat case %1$s · benign case %2$s'),
            $tug['support'],
            $tug['dispute']
        )),
    )) ?>
    <div class="px-3 pt-3">
        <div class="vp-tug-block">
            <div class="vp-tug-heads">
                <span class="vp-tug-head-mal">
                    <?= h(sprintf(
                        __('Threat case %s'),
                        $tug['support']
                    )) ?>
                </span>
                <span class="vp-tug-head-ben">
                    <?= h(sprintf(
                        __('%s benign case'),
                        $tug['dispute']
                    )) ?>
                </span>
            </div>
            <div class="vp-tug">
                <span class="vp-tug-mal" style="width: <?= round(
                    $tug['support'] / $tugTotal * 100,
                    2
                ) ?>%;"></span>
                <span class="vp-tug-ben" style="width: <?= round(
                    $tug['dispute'] / $tugTotal * 100,
                    2
                ) ?>%;"></span>
            </div>
            <?php /*
             * Two feet under two wedges. The middle one printed
             * *"%s unresolved"* from a count that had nothing to do
             * with the wedge above it (§7.8), and what it was reaching
             * for is now a card of its own further down — where it can
             * say what each item is instead of how many there are.
             */ ?>
            <div class="vp-tug-feet vp-tug-feet-pair">
                <span><?= h(sprintf(
                    __n('%d signal', '%d signals',
                        count($cases[0]['rows'])),
                    count($cases[0]['rows'])
                )) ?></span>
                <span><?= h(sprintf(
                    __n('%d signal', '%d signals',
                        count($cases[1]['rows'])),
                    count($cases[1]['rows'])
                )) ?></span>
            </div>
        </div>

    </div>
    <div class="vp-vc-cases">
        <?php foreach ($cases as $case):
            $mal = $case['side'] === 'threat';
            ?>
            <div class="vp-vc-case vp-vc-case-<?= $mal
                ? 'malicious'
                : 'benign' ?>">
                <div class="vp-vc-case-head">
                    <span class="vp-vc-case-arrow">
                        <?= $mal ? '&#9650;' : '&#9660;' ?>
                    </span>
                    <span class="vp-vc-case-title">
                        <?= h(sprintf(
                            __('%1$s — %2$s'),
                            $case['title'],
                            $case['weight']
                        )) ?>
                    </span>
                    <span class="vp-vc-case-count">
                        <?= h(sprintf(
                            __('%s signals'),
                            count($case['rows'])
                        )) ?>
                    </span>
                </div>
                <?php foreach ($case['rows'] as $row): ?>
                    <div class="vp-vc-row">
                        <div class="vp-vc-row-top">
                            <?php if (empty($row['tab'])): ?>
                                <span class="vp-vc-signal">
                                    <?= h($row['signal']) ?>
                                </span>
                            <?php else: ?>
                                <a class="vp-vc-signal vp-ledger-signal-link"
                                   href="#tab-<?= h($row['tab']) ?>"
                                   title="<?= h(__(
                                       'Open the tab holding this evidence'
                                   )) ?>">
                                    <?= h($row['signal']) ?>
                                </a>
                            <?php endif; ?>
                            <span class="vp-vc-bar"
                                  title="<?= h(sprintf(
                                      __('%s points'),
                                      $row['points']
                                  )) ?>">
                                <span class="vp-vc-bar-fill"
                                      style="width: <?= round(
                                          $row['points'] / $heaviest * 100,
                                          2
                                      ) ?>%;"></span>
                            </span>
                        </div>
                        <div class="vp-vc-row-bottom">
                            <span class="vp-vc-evidence">
                                <?= h($row['evidence']) ?>
                            </span>
                        </div>
                    </div>
                <?php endforeach; ?>
            </div>
        <?php endforeach; ?>
    </div>

    <?php
    /*
     * ----------------------------------------------------------
     * 5. What neither case could take
     * ----------------------------------------------------------
     * Contradictions the engine settled by rule rather than by
     * evidence. The heading used to read *counted for neither side*,
     * which was the one thing these items are not: a split
     * organisation **is** counted, with the asserters, and saying
     * otherwise would have a reader looking for points that are in the
     * column above. What is true of all of them is that a rule decided
     * where they went, so that is what the heading says.
     */
    ?>
    <?php if (!empty($ambiguities)): ?>
        <div class="vp-vc-unresolved">
            <div class="vp-vc-unresolved-head">
                <span class="vp-vc-unresolved-mark">&#9670;</span>
                <?= __('Contradictions') ?>
            </div>
            <div class="vp-vc-unresolved-body">
                <?php foreach ($ambiguities as $item): ?>
                    <div class="vp-vc-unresolved-item">
                        <div class="vp-vc-unresolved-title">
                            <?= h($item['title']) ?>
                        </div>
                        <div class="vp-vc-unresolved-note">
                            <?= h($item['note']) ?>
                        </div>
                    </div>
                <?php endforeach; ?>
            </div>
        </div>
    <?php endif; ?>

    <?php
    /*
     * ----------------------------------------------------------
     * 6. The clock
     * ----------------------------------------------------------
     * The same band as the agreeing layout, and it belongs here more
     * rather than less: a contested value is the one a reader is most
     * likely to go and check, and *how old is this disagreement* is the
     * first question they ask. §13.3's lesson, one layout across — a
     * fact that reaches only one of these two templates reaches roughly
     * half the values on the instance.
     */
    ?>
</div>

<?= $this->element('Values/View/value_verdict_relevance', array('verdict' => $verdict)) ?>
