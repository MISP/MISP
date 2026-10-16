<?php
/**
 * The lean band — how this reading was decided.
 *
 * The clock band's sibling, and the last of D11's three axes to get
 * its working onto the page. `10-wiring.md` §13.3 wired up the one
 * exit that had prose — a loaded conflict rule — and left six that had
 * none, so an ordinary value stated *Asserted threat* above a
 * provenance line reading *Computed at render · Analyst profile
 * default-v1* and nothing else. The organisations that decided it were
 * listed further down in *Who says what*; the arithmetic that turned
 * those rows into a lean was nowhere at all.
 *
 * **It costs no query.** `stances` is computed by
 * `ValueLeanTool::stancesFor()` on every value and, until this band,
 * was read by no template in the application — the same shape
 * `$verdict['relevance']` was in before §17: already built, discarded
 * at render.
 *
 * The counts and the bar are `value_verdict_stance`, which the
 * Overview's Assessment card draws too.
 *
 * @var array $verdict The assessment, carrying `stances`, `decided_by`
 *                     and `rule_errors`
 */
App::uses('ValueLean', 'Tools/ValueIntelligence');
App::uses('ValueLeanReasonTool', 'Tools/ValueIntelligence');

$reason = ValueLeanReasonTool::reasonFor($verdict);
$stances = isset($verdict['stances']) && is_array($verdict['stances'])
    ? $verdict['stances']
    : array();
$errors = isset($verdict['rule_errors'])
    && is_array($verdict['rule_errors'])
    ? $verdict['rule_errors']
    : array();

/*
 * The lean ledger, which belongs here and used to be filed with the
 * signal strength's. `review-2026-09-13.md` §D1 took the two axes apart: the
 * warninglist's hits and false-positive sightings are the only rows
 * that read the *value*, so they are the only rows that anchor — and
 * that leaves them out of the table below, which now sums to the
 * signal strength alone.
 *
 * They cannot simply disappear with it. A `−38` listing is the
 * heaviest thing on a benign record and the band above says the
 * reading was decided; these rows are how much weight was behind that
 * decision, which is the one question the stance counts cannot answer.
 */
$leanRows = isset($verdict['lean_ledger'])
    && is_array($verdict['lean_ledger'])
    ? $verdict['lean_ledger']
    : array();
$leanWeight = (int)(isset($verdict['lean_weight'])
    ? $verdict['lean_weight']
    : 0);
$leanBenign = ($verdict['lean'] ?? null) === 'benign';
$leanScale = $leanBenign
    ? __('On this value, + points push toward harmless and − points'
        . ' toward threat.')
    : __('On this value, + points push toward threat and − points'
        . ' toward harmless.');
$leanHeaviest = 1;
foreach ($leanRows as $leanRow) {
    $leanHeaviest = max(
        $leanHeaviest,
        abs((int)$leanRow['contribution'])
    );
}

/*
 * No sentence, no band. That is the empty record — whose hero already
 * says there is nothing to assess, and §17.4's argument applies
 * unchanged — and any exit a future rule adds without giving it words,
 * which should draw nothing rather than an empty frame.
 */
if ($reason === null) {
    return;
}

$total = (int)(isset($stances['orgs']) ? $stances['orgs'] : 0);
$context = (int)($stances['unflagged_orgs'] ?? 0);
?>
<div class="vp-vc-lean">
    <div class="vp-vc-lean-head"
         title="<?= h(__('Each organisation is one voice, at its'
             . ' reliability grade once you grade anybody. False'
             . ' positives and graded outside verdicts are voices'
             . ' too, and a supermajority on either side sets the'
             . ' reading. An organisation that only recorded it with'
             . ' to_ids unset casts no vote.')) ?>">
        <i class="fas fa-scale-balanced vp-vc-lean-mark"></i>
        <?= h(__('Lean')) ?>
        <span class="vp-vc-axis-head-sub">
            <?= h(__('how this reading was decided')) ?>
        </span>
        <span class="vp-vc-axis-head-total">
            <?= h(ValueLean::label($verdict['lean'] ?? 'none')) ?>
        </span>
    </div>
    <div class="vp-vc-lean-body<?= empty($leanRows)
        ? ''
        : ' vp-vc-band-split' ?>">

        <div class="vp-vc-band-bar">
        <?php if ($total > 0 || $context > 0): ?>
            <?= $this->element('Values/View/value_verdict_stance', array(
                'verdict' => $verdict,
                'stanceWide' => true,
            )) ?>
        <?php endif; ?>

        <p class="vp-vc-lean-note"><?= h($reason) ?></p>
        </div>

        <div class="vp-vc-band-list">
        <?php
        /*
         * The lean evidence. Stance counts are one
         * organisation, one vote; these are the rows that carry a
         * weight, so both the count and the weight are on the page and
         * a reader can see which of the two decided.
         *
         * Signed against the lean, like the ledger's own rows: `+38`
         * is a row supporting the reading stated above, `−38` one
         * disputing it. On a contested lean the rows are threat-signed
         * — rule 7 put them back — so a negative row is the half of
         * the contradiction arguing benign.
         */
        ?>
        <?php if (!empty($leanRows)): ?>
            <div class="vp-vc-lean-rows">
                <div class="vp-vc-lean-rows-head">
                    <?= h(__('Lean evidence')) ?>
                    <span class="vp-vc-lean-rows-total"
                          title="<?= h(__(
                              'These rows sum to this. Green argues'
                              . ' harmless, red argues threat.'
                          ) . ' ' . $leanScale . ' ' . __(
                              'Not part of the signal strength.'
                          )) ?>">
                        <?= h(($leanWeight > 0 ? '+' : '') . $leanWeight) ?>
                    </span>
                </div>
                <?php foreach ($leanRows as $leanRow):
                    $leanUp = (int)$leanRow['contribution'] >= 0;
                    $leanPoints = abs((int)$leanRow['contribution']);
                    /*
                     * The colour is the side the row argues for; the
                     * sign is measured against the reading, so a row
                     * arguing harmless on a threat reading is green
                     * and negative.
                     */
                    $leanTip = ($leanUp !== $leanBenign
                        ? __('Argues threat (red).')
                        : __('Argues harmless (green).'))
                        . ' ' . $leanScale;
                    ?>
                    <div class="vp-vc-lean-row<?= $leanUp
                        ? ' vp-vc-lean-row-up'
                        : ' vp-vc-lean-row-down' ?>"
                         title="<?= h($leanTip) ?>">
                        <span class="vp-vc-lean-row-mark">
                            <?= $leanUp ? '&#9650;' : '&#9660;' ?>
                        </span>
                        <span class="vp-vc-lean-row-signal">
                            <?= h($leanRow['signal']) ?>
                            <span class="vp-vc-lean-row-evidence">
                                <?= h($leanRow['evidence']) ?>
                            </span>
                        </span>
                        <span class="vp-vc-lean-row-bar">
                            <span class="vp-vc-lean-row-fill"
                                  style="width: <?= round(
                                      $leanPoints / $leanHeaviest * 100,
                                      2
                                  ) ?>%;"></span>
                        </span>
                        <span class="vp-vc-lean-row-points">
                            <?= h(((int)$leanRow['contribution'] > 0
                                ? '+'
                                : '') . (int)$leanRow['contribution']) ?>
                        </span>
                    </div>
                <?php endforeach; ?>
            </div>
        <?php endif; ?>

        <?php if (!empty($errors)): ?>
            <?php
            /*
             * The other key nothing read. `ruleErrors()` exists so that
             * a conflict rule the profile enables but the loader
             * cannot run reaches the reader as well as the admin — and
             * it reached neither, because no template asked for it. It
             * belongs in this band rather than anywhere else: a rule
             * that did not run is a reason this reading might have
             * been a different one.
             */
            ?>
            <div class="vp-vc-lean-errors">
                <?= h(__n(
                    'A conflict rule this profile enables did not run:',
                    'Conflict rules this profile enables did not run:',
                    count($errors)
                )) ?>
                <?php foreach ($errors as $error): ?>
                    <div class="vp-vc-lean-error">
                        <span class="font-monospace">
                            <?= h($error['id']) ?>
                        </span>
                        <?= h($error['note']) ?>
                    </div>
                <?php endforeach; ?>
            </div>
        <?php endif; ?>
        </div>

    </div>
</div>
