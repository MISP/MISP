<?php
/**
 * The Assessment tab for a value whose record contradicts itself.
 *
 * One card, not five. The lean, what it rests on, the warninglist hit
 * that causes half the trouble, the two cases and what neither case
 * could take are a single argument, and splitting them into separate
 * cards made the reader reassemble it. They are bands of one card here,
 * in the order the argument is made.
 *
 * There is deliberately no single signal strength. The tug-of-war bar puts the
 * two weights against each other — **two wedges, not three**: the
 * engine produces no `unresolved` weight to draw between them.
 *
 * `Who says what` stays its own card: it is the same argument counted
 * a different way, by organisation rather than by signal.
 *
 * Lazily loaded into `.ajax-tab-content` from
 * ValuesController::viewVerdict.
 *
 * @var array $valueIntelligence
 * @var string $valueB64
 */
App::uses('ValueLean', 'Tools/ValueIntelligence');

$verdict = $valueIntelligence['verdict'];

$noWrites = __(
    'Disabled in this pass — the Value Intelligence page does not write to'
    . ' the database yet.'
);

$tug = $verdict['tug'];
$tugTotal = max($tug['support'] + $tug['dispute'], 1);

$cases = $verdict['cases'];
$ambiguities = $verdict['ambiguities'] ?? array();
$warninglist = $verdict['warninglist'] ?? null;

/*
 * The row bars are read against the heaviest signal on either side, so
 * a strong signal looks strong in both columns. Scaling each column to
 * its own maximum would make the weaker case look just as emphatic.
 */
$heaviest = 1;
foreach ($cases as $case) {
    foreach ($case['rows'] as $row) {
        $heaviest = max($heaviest, (int)$row['points']);
    }
}
?>

<div class="card shadow-sm mb-3 vp-panel vp-vc">

    <?php
    /*
     * ----------------------------------------------------------
     * 1. Hero — the state, the reason, and the balance
     * ----------------------------------------------------------
     */
    ?>
    <div class="vp-vc-hero">
        <span class="vp-vc-state">
            <i class="<?= h(ValueLean::icon($verdict['lean'])) ?>"></i>
            <span class="vp-vc-state-word">
                <?= h(ValueLean::label($verdict['lean'])) ?>
            </span>
        </span>

        <?php if (!empty($verdict['summary'])): ?>
            <p class="vp-vc-prose"><?= h($verdict['summary']) ?></p>
        <?php endif; ?>

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

        <?= $this->element('Values/View/value_verdict_runway', array(
            'relevance' => $verdict['relevance'] ?? array(),
        )) ?>
    </div>

    <?php
    /*
     * ----------------------------------------------------------
     * 2. Provenance and the rule that fired
     * ----------------------------------------------------------
     */
    ?>
    <?= $this->element('Values/View/value_verdict_meta', array(
        'verdict' => $verdict,
        'metaRule' => $verdict['rule']['text'] ?? null,
    )) ?>

    <?php
    /*
     * ----------------------------------------------------------
     * 2b. How the lean was decided
     * ----------------------------------------------------------
     * It matters more here than on the agreeing layout. A contested
     * value reached by rule 6 — neither side past the bar — draws two
     * cases side by side and had no sentence anywhere saying *why*,
     * because the only prose in the derivation belongs to the
     * escalation exit this value did not take.
     */
    ?>
    <?= $this->element('Values/View/value_verdict_lean', array(
        'verdict' => $verdict,
    )) ?>

    <?php
    /*
     * ----------------------------------------------------------
     * 3. The warninglist hit
     * ----------------------------------------------------------
     * A band rather than a card, because on this value it is one of the
     * two cases talking — not a separate finding.
     */
    ?>
    <?php if ($warninglist !== null): ?>
        <?= $this->element('Values/View/value_verdict_warninglist', array(
            'warninglist' => $warninglist,
        )) ?>
    <?php endif; ?>

    <?php
    /*
     * ----------------------------------------------------------
     * 4. The two cases
     * ----------------------------------------------------------
     * Side by side and the same shape, so the comparison is between the
     * evidence rather than between two presentations of it.
     */
    ?>
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
    <?= $this->element('Values/View/value_verdict_relevance', array(
        'verdict' => $verdict,
    )) ?>

</div>

<?php
/*
 * ------------------------------------------------------------------
 * Who says what
 * ------------------------------------------------------------------
 * The disagreement is between organisations, so it is also shown per
 * organisation — and on this layout the stance and the grade are the
 * columns that carry it: which organisations would have the value fire
 * a rule, and how much each one's say is worth.
 */
?>
<?= $this->element('Values/View/value_verdict_orgs', array(
    'verdict' => $verdict,
    'orgColumns' => array('to_ids', 'reliability'),
    'orgsSub' => __(
        'The disagreement is between organisations, so it is shown per'
        . ' organisation'
    ),
)) ?>
