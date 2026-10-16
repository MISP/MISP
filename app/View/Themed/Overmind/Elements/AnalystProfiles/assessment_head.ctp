<?php
/**
 * The assessment: lean, relevance and signal strength, at one rank.
 *
 * Signal strength is the only axis with an additive ledger, so it is the only
 * one a design can show its work for — and every prototype in 8b put
 * its visual mass there and listed the other two as fields. Two of the
 * three axes ended up rendered as peers of *"saved: nothing, ever"*.
 * Three cells of equal width is the correction, and the relation
 * between them is stated once underneath rather than left to be
 * inferred from the layout.
 *
 * @var array $axes From the diff — each axis as before/after/changed
 * @var bool $moved Whether anything moved at all
 */
App::uses('ValueRelevanceTool', 'Tools/ValueIntelligence');
$lean = $axes['lean'];
$relevance = $axes['relevance'];
$signalStrength = $axes['signal_strength'];
$band = $axes['band'];
$runway = isset($relevance['runway']) ? $relevance['runway'] : null;
?>
<div class="bench-ax3">
    <div class="ax">
        <span class="ax-n"><?= h(__('lean')) ?></span>
        <b class="ax-v"><?= h($lean['after'] === null
            ? __('none') : $lean['after']) ?></b>
        <?php if (!empty($lean['changed'])): ?>
            <span class="ax-was"><?= h(sprintf(
                __('was %s'), $lean['before'] === null
                    ? __('none') : $lean['before']
            )) ?></span>
        <?php endif; ?>
        <span class="ax-g"><?= h(__('what the record asserts')) ?></span>
    </div>
    <div class="ax">
        <span class="ax-n"><?= h(__('relevance')) ?></span>
        <b class="ax-v"><?= $relevance['after'] === null
            ? h(__('no clock'))
            : h(isset($relevance['label']) && $relevance['label'] !== ''
                ? $relevance['label']
                : $relevance['after']) ?></b>
        <?php if (!empty($relevance['changed'])): ?>
            <span class="ax-was"><?= h(sprintf(
                __('was %s'), $relevance['before'] === null
                    ? __('no clock') : $relevance['before']
            )) ?></span>
        <?php endif; ?>
        <span class="ax-g"><?= h(__('whether it still holds')) ?></span>
        <?= $this->element('AnalystProfiles/runway', array(
            'runway' => $runway,
        )) ?>

    </div>
    <div class="ax ax-led">
        <span class="ax-n"><?= h(__('signal strength')) ?></span>
        <b class="ax-v num">
            <?= h($signalStrength['after']) ?>
            <?php if (!empty($signalStrength['changed'])): ?>
                <span class="ax-was"><?= h(sprintf(
                    __('was %s'), $signalStrength['before']
                )) ?></span>
            <?php endif; ?>
        </b>
        <span class="ax-g">
            <?= h(__('how well evidenced')) ?> &middot;
            <?= h(__('band')) ?> <b><?= h($band['after']) ?></b>
            <?php if (!empty($band['changed'])): ?>
                <span class="ax-was"><?= h(sprintf(
                    __('was %s'), $band['before']
                )) ?></span>
            <?php endif; ?>
        </span>
    </div>
</div>
<p class="bench-rel">
    <?php
    /*
     * One line on screen, the rest behind the `i` — 09b-revisions §3.7
     * asked for that length and this is it. The wording is the plain
     * one: *lean axis*, *signal-strength axis* and *anchored row* are exact
     * and they are also the phrases a reader has to already know the
     * model to parse, which is the wrong way round for the sentence
     * whose job is teaching the model.
     *
     * Rewritten 2026-09-15. The `i` taught the anchoring — *if the
     * lean came out benign, that whole scale is flipped* — which
     * `review-2026-09-13.md` §D1 retired and §G2's four-surface pass
     * did not reach. It is the same sentence
     * `AnalystProfileFormTool::sectionSignals()` was rewritten away
     * from, and it now carries the same two axes in the same words.
     */
    ?>
    <?= sprintf(
        h(__('Three readings, not one score: %1$slean%2$s is what the'
            . ' record says this value is, %1$ssignal strength%2$s is how'
            . ' well backed up that is, and %1$srelevance%2$s is whether'
            . ' it still holds.')),
        '<b>',
        '</b>'
    ) ?>
    <a href="#" class="wb-i" onclick="return false;"
       title="<?= h(__("The lean is counted from how many organisations"
           . " flagged this value for detection and how many said it is"
           . " harmless, with a false positive or a warning. Recording"
           . " it with to_ids unset is no vote. No points are"
           . " involved.\n\n"
           . "Signal strength is the points: a plus means the record carries"
           . " something — widely reported, published, attributed — and"
           . " a minus that it does not, whichever way the lean came"
           . " out.\n\n"
           . "Two signals are marked \"reads the value\": a warninglist"
           . " hit and a false-positive sighting. Those argue for or"
           . " against the lean instead, and are counted separately.\n\n"
           . "Relevance is a clock and touches neither.")) ?>">i</a>
    <?php if ($lean['after'] === 'contested'): ?>
        <?= h(__('This value is contested, so the rows that read it'
            . ' render threat-signed.')) ?>
    <?php elseif ($lean['after'] === 'unflagged'): ?>
        <?= h(__('Nobody flagged this value for detection and nobody'
            . ' called it harmless, so it reads as recorded for context;'
            . ' the signal strength still scores the record.')) ?>
    <?php elseif ($lean['after'] === 'none'): ?>
        <?= h(__('This value has a lean of none, so there is no ledger'
            . ' at all.')) ?>
    <?php endif; ?>
</p>
<?php
/*
 * The dates the relevance axis is built on — the same element the value
 * page's Lifetime card draws, because a reader tuning
 * `undated_assumed_days` three fields away is exactly the reader who
 * needs to know whether this value declares a `first_seen` at all.
 *
 * **Below the strip, not inside it.** The first attempt put it in the
 * relevance column, which is one third of the bench: 125px for three
 * columns, and `Attribute.first_seen` overlapped the cell beside it.
 * The strip is three readings side by side; this is one table about
 * one of them, and it needs the width.
 *
 * Folded shut. The bench is an assessment, not a reference table.
 */
?>
<?php if (!empty($dates) && !empty($runway['clock'])): ?>
    <div class="bench-dates">
        <?= $this->element('Values/View/value_date_sources', array(
            'facts' => $dates,
            'clockKind' => $runway['clock']['kind'] ?? null,
            'clockLabel' => ValueRelevanceTool::clockLabel(
                $runway['clock']['setting'] ?? null
            ),
            'lastSighting' => $lastSighting ?? null,
            'sightingTotal' => $sightingTotal ?? 0,
        )) ?>
    </div>
<?php endif; ?>
