<?php
/**
 * The Assessment tab for a value whose signals agree.
 *
 * Agreeing, not threatening: a value everything points away from is the
 * same kind of argument as one everything points at, made in the same
 * shape, and it earns the same layout. What changes between a `threat`
 * lean and a `benign` one is the colour, the glyph, and whether there
 * is a warninglist band — none of which is a reason for a second
 * template. Only `contested` gets one, because two irreconcilable cases
 * genuinely do not fit a single ledger.
 *
 * One card, not four. The lean, its provenance, the listing that drives
 * it where there is one, the signals behind it and the contradictions
 * that survived are a single argument, and separate cards made the
 * reader reassemble it. They are bands of one card here, in the order
 * the argument is made.
 *
 * `Who says what` stays its own card — the same argument counted a
 * different way, by organisation rather than by signal.
 *
 * The arithmetic, the trend, the exclusions and what would falsify the
 * assessment live in the rail, from `value_verdict_aside`.
 *
 * Lazily loaded into `.ajax-tab-content` from
 * ValuesController::viewVerdict.
 *
 * @var array $valueIntelligence
 * @var string $valueB64
 */
App::uses('ValueLean', 'Tools/ValueIntelligence');

$verdict = $valueIntelligence['verdict'];

$uid = 'vp' . substr(md5($valueIntelligence['value'] . '-verdict'), 0, 8);

$lean = $verdict['lean'];
$treatment = ValueLean::treatment($lean);
$signalStrength = $verdict['signal_strength'];
$warninglist = $verdict['warninglist'] ?? null;

/*
 * Signal strength reads as **how much record there is**, and it says so —
 * `review-2026-09-13.md` §D1. It used to read *how strongly the record
 * supports <the lean>*, which was the anchoring's own claim: every row
 * was multiplied by the lean's polarity, so the number really did
 * measure support for the badge above it. It no longer is and no
 * longer does. The rows that support or dispute the lean are in the
 * band under the provenance line, summing to their own figure; this
 * one counts corroboration, publication, attribution and temporal
 * precision, and counts them the same whatever the reading turned out
 * to be.
 *
 * One ruler either way, so two values stay comparable — which is what
 * the sentence this replaces was really defending.
 */
$signalStrengthLabel = __(
    'How well documented the record is: corroboration, publication,'
    . ' attribution, dates. Not whether the value is a threat.'
);

?>

<div class="card shadow-sm mb-3 vp-panel vp-vc vp-vc-agreeing
            vp-vc-<?= h($treatment['slug']) ?>"
     style="--vp-vc-color: <?= h($treatment['colour']) ?>;
            --vp-vc-ink: <?= h($treatment['ink']) ?>;
            <?= h(ValueLean::directionStyle($lean)) ?>">

    <?php
    /*
     * ----------------------------------------------------------
     * 1. Hero — the lean, the signal strength, and the reason
     * ----------------------------------------------------------
     */
    ?>
    <div class="vp-vc-hero">
        <?php
        /*
         * A `none` lean arrives here too — this layout carries every
         * value whose signals do not contradict each other, including
         * the ones with no signals at all. A solid badge in the same
         * weight as *Asserted threat* would state a conclusion where
         * there is none, so a lean that refuses to name a state is
         * drawn quietly.
         */
        ?>
        <span class="vp-vc-badge<?= $treatment['definite']
            ? ''
            : ' vp-vc-badge-quiet' ?>">
            <i class="<?= h($treatment['icon']) ?>"></i>
            <?= h(ValueLean::label($lean)) ?>
        </span>

        <?php /*
         * The hero's paragraph, drawn only where there is one to draw.
         * `summary` is the key D11 left open — the composition of lean,
         * relevance and signal strength into a sentence — and
         * `ValueSummaryTool` has written it since 2026-09-13
         * (`prd/analyst-profile/10-wiring.md` §13). The guard stays: a
         * lean with nothing weighed behind it stops the sentence after
         * one clause, and the builder returns nothing rather than a
         * fragment. The bands below state the same argument in rows, so
         * the card is complete without it.
         *
         * **Next to the badge, not after the gauge.** The badge names
         * the reading and this sentence is that reading in full, so a
         * number wedged between them made the eye cross a third object
         * to finish a thought. The gauge follows instead, against the
         * far margin, where it reads as the one figure the card leaves
         * you with.
         */ ?>
        <?php if (!empty($verdict['summary'])): ?>
            <p class="vp-vc-prose vp-vc-prose-wide">
                <?= h($verdict['summary']) ?>
            </p>
        <?php endif; ?>

        <?php
        /*
         * The gauge, where something was weighed. A `none` band means
         * no signal contributed, and `0 / 100` under it read as
         * *scored, and badly* rather than *not scored*
         * (`review-2026-09-13.md` §C3) — on a card whose own sentence
         * says there is nothing to assess, the number was the only
         * thing on it that was not true.
         */
        ?>
        <?php if ($signalStrength !== null && $verdict['band'] !== 'none'): ?>
            <div class="vp-vc-score" title="<?= h($signalStrengthLabel) ?>">
                <div class="vp-vc-score-heads">
                    <span><?= h(sprintf(
                        __('Signal strength %s'),
                        $verdict['band']
                    )) ?></span>
                    <span class="vp-vc-score-value">
                        <?= h($signalStrength) ?> / 100
                    </span>
                </div>
                <?php /*
                 * Clamped, because a signal strength can be negative: the
                 * ledger sums to it exactly,
                 * so a record with more absences than substance nets
                 * below zero — `awake-weaves.cyou` closes at −1 on the
                 * dev instance, one organisation and nothing else. A
                 * negative width is an invalid declaration the browser
                 * drops, which leaves the fill at whatever width it
                 * inherits rather than at empty. The number beside it
                 * is printed unclamped, because that one is the
                 * assessment.
                 *
                 * **Not a record disputing its own lean**, which is
                 * what this said before `review-2026-09-13.md` §D1
                 * moved the lean rows to their own ledger. Evidence
                 * that argues with the reading now sums into
                 * `lean_weight` and can no longer reach this number;
                 * `8.8.8.8`, the old worked example, closes at +57
                 * where it closed at −1. Whether the absence poles
                 * should floor here is the profile's calibration
                 * question, not this element's — §F.
                 */ ?>
                <?php
                /*
                 * The band floors, on the bar the band is named above.
                 *
                 * Every other axis on this card draws its thresholds:
                 * the lean's track carries both supermajority marks and
                 * the clock's carries the day it expires. Signal strength
                 * printed a word — `Signal strength medium` — over a bar with
                 * nothing on it, and the only thing that said where
                 * `medium` starts was a sentence under a table 500px
                 * further down. Same grammar, same two-pixel mark, and
                 * the ledger's foot still owns the sentence, including
                 * the two cases where the floor is not what decided the
                 * band at all (`10-wiring.md` §19).
                 */
                $floors = isset($verdict['band_reason']['floors'])
                    && is_array($verdict['band_reason']['floors'])
                    ? $verdict['band_reason']['floors']
                    : array();
                $marks = array(
                    'medium' => (int)(isset($floors['medium'])
                        ? $floors['medium'] : 30),
                    'high' => (int)(isset($floors['high'])
                        ? $floors['high'] : 60),
                );
                ?>
                <div class="vp-vc-score-track">
                    <span class="vp-vc-score-fill"
                          style="width: <?= max(0, min(100, (int)$signalStrength)) ?>%;"
                    ></span>
                    <?php foreach ($marks as $band => $at): ?>
                        <?php if ($at > 0 && $at < 100): ?>
                            <span class="vp-vc-score-mark"
                                  title="<?= h(sprintf(
                                      __('%1$s starts at %2$s'),
                                      ucfirst($band),
                                      $at
                                  )) ?>"
                                  style="left: <?= $at ?>%;"></span>
                        <?php endif; ?>
                    <?php endforeach; ?>
                </div>
            </div>
        <?php endif; ?>

        <?= $this->element('Values/View/value_verdict_runway', array(
            'relevance' => $verdict['relevance'] ?? array(),
        )) ?>

    </div>

    <?php
    /*
     * ----------------------------------------------------------
     * 2. Provenance
     * ----------------------------------------------------------
     */
    ?>
    <?php /*
     * The rule travels on this layout too, and it did not until phase
     * 9's hero pass. A contested lean reaches *this* template whenever
     * `cases` is empty — which is every contested value today
     * (`ValueLean::hasConflictedLayout`) — so the escalation that
     * decided the lean was being computed, given prose, and shown
     * nowhere. `8.8.8.8` is exactly that value.
     *
     * Absent on an agreeing lean, where `rule` is null and the meta
     * line falls back to the storage note. Nothing is crowded out: a
     * record with no rule has no rule to print.
     */ ?>
    <?= $this->element('Values/View/value_verdict_meta', array(
        'verdict' => $verdict,
        'metaRule' => $verdict['rule']['text'] ?? null,
    )) ?>

    <?php
    /*
     * ----------------------------------------------------------
     * 2b. How the lean was decided
     * ----------------------------------------------------------
     * Directly under the provenance, because on the one exit that
     * already had prose the band's sentence points at the line above
     * — and because the two bands below it, the warninglist and the
     * ledger, are both evidence this reading was reached *despite* or
     * *because of*. The reader meets the rule before the evidence for
     * it.
     */
    ?>
    <?= $this->element('Values/View/value_verdict_lean', array(
        'verdict' => $verdict,
    )) ?>

    <?php
    /*
     * ----------------------------------------------------------
     * 3. The listing, where one drives the lean
     * ----------------------------------------------------------
     * A threat-leaning value that hits no warninglist has no band here
     * and says so in the ledger instead, as one weak signal among many.
     * A benign-leaning one usually has the band, and it is usually the
     * heaviest row in the ledger below.
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
     * 4. The ledger
     * ----------------------------------------------------------
     */
    ?>
    <?= $this->element('Values/View/value_verdict_ledger', array(
        'verdict' => $verdict,
    )) ?>

    <?php
    /*
     * ----------------------------------------------------------
     * 5. The clock
     * ----------------------------------------------------------
     * Last, because it is the axis that argues with neither of the
     * others — a value can be well evidenced and out of date, and the
     * ledger above has already finished saying how well evidenced.
     * It is in the card rather than the rail because D11's three axes
     * are peers, and the two that were drawn here were the two a
     * reader could audit.
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
 * Consensus is itself a signal, so it is shown per source. The
 * trailing columns are the ones that matter when the signals agree:
 * whether each organisation would have the value fire a rule, and how
 * much its say is worth.
 */
?>
<?= $this->element('Values/View/value_verdict_orgs', array(
    'verdict' => $verdict,
    'orgColumns' => array('to_ids', 'reliability'),
    'orgsSub' => __('One row per organisation'),
)) ?>
