<?php
/**
 * The clock band — relevance, at the rank the other two axes have.
 *
 * D11's three axes were not three on this tab. Lean carried its badge,
 * the escalation that decided it and a table of who says what; signal strength
 * carried the number, the band and a ledger whose rows sum to it
 * exactly. Relevance carried one clause of the hero's sentence and a
 * 90-day line in the rail — a reader could see *what* the axis
 * concluded and nothing of *why*, on the one axis whose inputs are
 * dates a reader can go and check.
 *
 * **A band rather than a card, and rather than a number in the hero.**
 * D11 §7 rules out the obvious fix: three competing numbers at the top
 * is what the one-number verdict was replaced for, and `summary`
 * already composes the three axes in a sentence. What was missing is
 * the axis's working, and the argument card is where this tab keeps
 * working — the warninglist band and the ledger are its neighbours, in
 * the order the argument is made.
 *
 * It costs no query. `$verdict['relevance']` is built inside
 * `ValueVerdictTool::assess()` from the context the signal strength already
 * read, so every fact drawn here was on the tab before this band
 * existed and was being thrown away at render.
 *
 * The facts and the corroboration list are the Lifetime card's own
 * elements, not copies of them. `10-wiring.md` §14.3 is why: this tab
 * drew *expired, 33 days over* while the Sightings tab drew *64 days
 * left* for one value on one page, and two panels computing one
 * quantity twice is a defect this corpus has now shipped three times.
 * A shared element cannot disagree with itself.
 *
 * @var array $verdict The assessment, carrying `relevance`
 */
$relevance = $verdict['relevance'] ?? array();
$clock = $relevance['clock'] ?? array();

/*
 * The one value this band has nothing to add to: a record the viewer
 * holds nothing of. `no_record` is `clock.at === null`, which is the
 * same condition the lean's first rule reads to return `none`, so the
 * hero has already said *nothing you can see records this value* and a
 * band repeating it in the clock's words is a second empty state under
 * the first. Every other silence is drawn, because every other silence
 * is about this axis rather than about the whole record.
 *
 * The Lifetime card keeps its own no-record state: it is the panel a
 * reader opens *for* the clock, and it is the only thing on that panel.
 */
if (($verdict['lean'] ?? null) === 'none'
    && ($relevance['state'] ?? null) === null
) {
    return;
}
?>
<div class="vp-vc-clock">
    <div class="vp-vc-clock-head"
         title="<?= h(__('Counts down from the last time someone'
             . ' independent confirmed the value. It affects neither'
             . ' the lean nor the signal strength.')) ?>">
        <i class="fas fa-hourglass-half vp-vc-clock-mark"></i>
        <?= h(__('How long this reading holds')) ?>
    </div>
    <div class="vp-vc-clock-body<?= empty($clock['events'])
        ? ''
        : ' vp-vc-band-split' ?>">
        <div class="vp-vc-band-bar">
            <?= $this->element('Values/View/value_relevance_facts', array(
                'relevance' => $relevance,
            )) ?>
        </div>
        <?php if (!empty($clock['events'])): ?>
            <?php
            /*
             * The nearest thing this axis has to the ledger above it:
             * the dates that produced the number, each attributed, the
             * one in force marked. Capped at four rather than the
             * Lifetime card's six — that card is the panel a reader
             * opens *for* the clock, and this is a band inside an
             * argument about something else.
             */
            ?>
            <div class="vp-vc-band-list">
                <?= $this->element(
                    'Values/View/value_relevance_events',
                    array('clock' => $clock, 'cap' => 4)
                ) ?>
            </div>
        <?php endif; ?>
        <?php
        /*
         * **The caption is three captions, because the two panels do
         * not always agree and saying they do is how §14.3 got
         * shipped.** On a value whose rows the budget left unread this
         * axis stands down while the Lifetime card still reads the rows
         * it did fetch — `github.com` is *stands down* here and
         * *current, 64 days left* there, and both are correct. A
         * reader who finds that difference unexplained files it as the
         * bug it looks like, so the difference is what the line says.
         * With nothing recorded at all there is no second panel to
         * point at and no bar to plot, so there is no line.
         */
        $reason = $relevance['reason'] ?? null;
        ?>
        <?php if (($relevance['state'] ?? null) !== null): ?>
            <p class="vp-vc-clock-note">
                <?= h(__('Full history in the Sightings tab\'s'
                    . ' Lifetime card.')) ?>
            </p>
        <?php elseif ($reason === 'rows_not_read'): ?>
            <p class="vp-vc-clock-note">
                <?= h(__('The Sightings tab\'s Lifetime card shows a'
                    . ' clock from the rows it could read, but it may'
                    . ' miss the newest confirmations.')) ?>
            </p>
        <?php endif; ?>
    </div>
</div>
