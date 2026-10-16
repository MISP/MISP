<?php
/**
 * One worklist row, assessed — **in both of its views at once**.
 *
 * What `ValuesController::assess()` answers, one request per value and
 * five in flight (`value-index.md` §7.3). The fragment replaces the
 * row's fill, and it carries the card body, the compact row's cells
 * and the row's actions together: the pick took A's compact table as a
 * *second view over one model* (`02a-contract.md` §12.3), so switching
 * views must lose neither the reader's place nor their decisions. One
 * fetch that draws both is how that is kept — the toggle is a class on
 * the list and nothing is re-fetched, re-rendered or re-ordered.
 *
 * The cells become the row's own grid items through `display: contents`
 * on their wrapper, so the columns align down the list without every
 * row's cells being hoisted into the markup by hand.
 *
 * **Produced from the payload alone.** No row index, no *found* flag,
 * nothing derived from whether the reader may see this value: §4.2
 * holds that a value the reader cannot see renders identically to one
 * nobody recorded, and that rule is a property of this file. The
 * engine answers both cases the same way and this must not reintroduce
 * the difference — which is checked as a byte diff of two rows rather
 * than by reading them (§7.3).
 *
 * Three axes and one hue: the lean owns the colour, signal strength is a
 * magnitude drawn with none, and relevance is a word plus a figure.
 * `value_hover_card.ctp` carries that argument at length; this row is
 * the same assessment at a list's density.
 *
 * @var array $assessment `value` and `card`, from
 *                        `ValueIntelligence::forHoverCard`
 */
App::uses('ValueLean', 'Tools/ValueIntelligence');
App::uses('ValueRelevanceTool', 'Tools/ValueIntelligence');
App::uses('ValueUrlTool', 'Tools/ValueIntelligence');

$card = $assessment['card'];
$treatment = ValueLean::treatment($card['lean']);
$counts = $card['counts'];
$relevance = $card['relevance'];

$profileUrl = $this->Html->url(array(
    'controller' => 'values',
    'action' => 'view',
    ValueUrlTool::address($assessment['value']),
));

/*
 * The state words are the contract's exactly (§9.1), and `uncertain`
 * is the only two-word one. `aging` with the uncertainty flag set is
 * not a fifth state and is not folded into one: the word says where
 * the value is in its lifetime and the qualifier says how much the
 * clock behind that is worth, and a reader cannot take a single token
 * apart again.
 *
 * Asked of `ValueRelevanceTool` rather than kept here. That accessor
 * exists because the copies of these four strings had already drifted
 * once — one surface printed `uncertain` raw where the rest said
 * *timeline uncertain* — and phase 8's method note now draws the same
 * four as a legend for these rows. A legend disagreeing with the rows
 * it explains is the worst place yet for the next drift, and two
 * writers is how it would happen.
 */
$relevanceState = $relevance['state'];
$relevanceWord = ValueRelevanceTool::stateLabel($relevanceState);
/*
 * No figure rather than a zero where the timeline is a floor: `0d`
 * against an *expired* caption reads as *expired today*, which is a
 * measurement this row never made.
 */
$runway = $relevance['runway_days'];
$runwayText = $runway === null
    ? '—'
    : ($runway < 0 ? '−' . abs($runway) : '+' . $runway) . 'd';

/*
 * The names alone. `ValueHoverTool` hands each chip its occurrence
 * count as well, and the hover card draws both — but the count is
 * already on this row twice over, in the occurrences figure and in the
 * compact view's columns, and a row is not the place to spend width
 * saying a third time what a value was filed as how often.
 */
$types = array();
foreach ($card['types']['shown'] as $type) {
    $types[] = $type['type'];
}
$typesText = $types
    ? implode(', ', $types)
        . ($card['types']['more'] ? ' +' . $card['types']['more'] : '')
    : '';

/*
 * The signal-strength bar, five segments of a fifth each. It carries the
 * magnitude and no hue at all — a bar that took a fourth colour would
 * make the row's one coloured thing stop being the lean.
 */
$signalStrength = $card['signal_strength'];
/*
 * Clamped at both ends: the engine's score can run below zero, and a
 * negative segment count would draw the bar backwards.
 */
$filled = $signalStrength === null
    ? 0
    : max(0, min(5, (int)round($signalStrength / 20)));
$bar = '';
for ($i = 0; $i < 5; $i++) {
    /*
     * **Filled solid, unfilled hollow** — `value-palette.css`'s own
     * pairing for *carries* against *lacks*. Drawing both as solid
     * fills in two greys is what the first version did, and at 4px
     * the two greys are one grey: a bar carrying the magnitude that
     * reads the same at 3 as at 97 is worse than no bar.
     */
    $bar .= '<rect x="' . ($i * 9 + 0.5) . '" y="0.5" width="6"'
        . ' height="3" rx="1" ' . ($i < $filled
            ? 'fill="var(--vi-carries)"'
            : 'fill="none" stroke="var(--vi-lacks)" stroke-width="1"')
        . '/>';
}
$barSvg = '<svg class="vi-qbar" width="43" height="4" viewBox="0 0 43 4"'
    . ' aria-hidden="true">' . $bar . '</svg>';

/*
 * The warninglist sentence, which the compact view has no line for and
 * may not simply drop (§12.8). It is the one that stops a reader taking
 * a strong-signal *Asserted benign* chip for a clean bill — neither
 * category means the reporting organisations were wrong — so the table
 * carries it as a mark against the value, titled with the sentence
 * itself. The card prints it in full a keystroke away.
 */
$warninglist = $card['warninglist'];
$warningNote = null;
if ($warninglist !== null) {
    $warningNote = trim(sprintf(
        '%s — %s. %s',
        $warninglist['category_label'],
        $warninglist['name'],
        $warninglist['note']
    ));
}

$signals = $card['signals'];

/**
 * The lean chip, drawn the same in both views and sized by the view.
 *
 * A lean that names no state is drawn quietly — the rule the hover
 * card, the tab pill and the Assessment hero all hold. A solid chip
 * reading *Contested* claims a certainty the record does not have.
 */
$leanChip = '<span class="vi-lean vi-lean--' . h($treatment['slug'])
    . '">' . ValueLean::quietMark($card['lean'])
    . h($treatment['label']) . '</span>';

$relevanceCell = '<span class="vi-relword vi-rel--'
    . h($relevanceState) . '">' . h($relevanceWord) . '</span>'
    . '<span class="vi-days">' . h($runwayText) . '</span>'
    . ($relevance['uncertain'] && $relevanceState !== 'uncertain'
        ? '<span class="vi-relq">' . h(__('timeline uncertain'))
            . '</span>'
        : '');

$signalText = function (array $signal) {
    return '<b>' . h(($signal['contribution'] < 0 ? '−' : '+')
        . abs($signal['contribution'])) . '</b>' . h($signal['text']);
};
?>
<?php
/*
 * The two facts the worst-first sort ranks on, carried as attributes
 * rather than read back out of the row's own prose: a sort that parsed
 * its own rendering would break the first time a chip's wording
 * changed. Both are payload-derived and both are the same for a value
 * nobody recorded and one the reader may not see, so §4.2 survives
 * them.
 */
?>
<div class="vi-card" data-vi-lean="<?= h($card['lean']) ?>"
     data-vi-signal-strength="<?= h($signalStrength === null ? '' : $signalStrength) ?>">
    <div class="vi-l1">
        <span class="vi-val"><?= h($card['value']) ?></span>
<?php if ($typesText !== ''): ?>
        <span class="vi-types"><?= h($typesText) ?></span>
<?php endif; ?>
<?php if ($counts['occurrences'] || $counts['orgs'] || $counts['events']): ?>
        <span class="vi-counts">
            <i><b><?= h(number_format($counts['orgs'])) ?></b>
                <?= h(__n('org', 'orgs', $counts['orgs'])) ?></i>
            <i><b><?= h(number_format($counts['events'])) ?></b>
                <?= h(__n('event', 'events', $counts['events'])) ?></i>
            <i><b><?= h(number_format($counts['occurrences'])) ?></b>
                <?= h(__n('occurrence', 'occurrences',
                    $counts['occurrences'])) ?></i>
<?php if ($counts['sightings'] === null): ?>
            <i><?= h(__('sightings skipped')) ?></i>
<?php else: ?>
            <i><b><?= h(number_format($counts['sightings'])) ?></b>
                <?= h(__n('sighting', 'sightings',
                    $counts['sightings'])) ?></i>
<?php endif; ?>
        </span>
<?php endif; ?>
    </div>
    <div class="vi-l2">
        <?= $leanChip ?>
<?php if ($signalStrength === null): ?>
        <span class="vi-strength"><?= h(__('signal strength not scored')) ?></span>
<?php else: ?>
        <span class="vi-strength"><b><?= h($signalStrength) ?></b><?= h($card['band']) ?><?= $barSvg ?></span>
<?php endif; ?>
        <span class="vi-rel"><?= $relevanceCell ?></span>
<?php
/*
 * The heaviest ledger row rides on line two while the row is shut. When
 * it is open the whole ledger is underneath, and printing the first row
 * twice is noise — so this one is hidden by the open state rather than
 * omitted, which keeps the two views' markup identical either way.
 */
?>
<?php if ($signals): ?>
        <span class="vi-sig vi-sig--top"><?= $signalText($signals[0]) ?></span>
<?php endif; ?>
    </div>
<?php
/*
 * Line three is what qualifies the two lines above it, and it is drawn
 * only where there is something to qualify. The order is the order a
 * reader needs it in: what this page did not measure, then what the
 * record says about the value's ordinariness, then what it names.
 */
$caveats = array();
if ($card['hot']) {
    $caveats[] = '<b>' . h(__('Sightings and threat actor clusters were'
        . ' skipped')) . '</b> — ' . h(__('this value is'
        . ' over-correlating, so they were not checked. Everything else'
        . ' on this row was.'));
}
if ($warninglist !== null) {
    $caveats[] = '<span class="vi-wlpill">'
        . '<i class="fas fa-list-check" aria-hidden="true"></i>'
        . h($warninglist['category_label']) . '</span> — '
        . h($warninglist['name'])
        . ($warninglist['more']
            ? ' <span>' . h(sprintf(__n('and %d other list',
                'and %d other lists', $warninglist['more']),
                $warninglist['more'])) . '</span>'
            : '')
        . '. ' . h($warninglist['note']);
}
if ($card['galaxy'] !== null) {
    $caveats[] = '<b>' . h($card['galaxy']['name']) . '</b> <span>'
        . h($card['galaxy']['sub_category']) . '</span>'
        . ($card['galaxy']['more']
            ? h(sprintf(__n(', and %d more cluster',
                ', and %d more clusters', $card['galaxy']['more']),
                $card['galaxy']['more']))
            : '');
}
/*
 * A value with nothing recorded has no caveat and no ledger, so its
 * row would otherwise be a value and four empty slots. The summary is
 * the sentence that says *nothing here records this*, which is an
 * answer rather than an absence — and it is the same sentence the
 * value the reader may not see gets.
 */
if (!$caveats && !$counts['occurrences'] && $card['lean'] === 'none'
    && $card['summary'] !== null
) {
    $caveats[] = h($card['summary']);
}
?>
<?php if ($caveats): ?>
    <div class="vi-l3"><?= implode('<br>', $caveats) ?></div>
<?php endif; ?>
    <div class="vi-l4">
<?php if ($card['summary'] !== null): ?>
        <div class="vi-summary"><?= h($card['summary']) ?></div>
<?php endif; ?>
<?php if ($signals): ?>
<?php foreach ($signals as $signal): ?>
        <div class="vi-sigrow"><span class="vi-sig"><?= $signalText($signal) ?></span></div>
<?php endforeach; ?>
<?php else: ?>
        <div class="vi-sigrow"><span class="vi-sig"><?= h(__(
            'No signal fired for this value.'
        )) ?></span></div>
<?php endif; ?>
    </div>
</div>
<?php
/*
 * The compact view. One line, fixed height, every column one line deep,
 * and what does not fit is not shown here rather than wrapped: a row
 * that grows with what it has to say is the card, and the card is one
 * keystroke away. §12.8 lists what is dropped — the summary, the whole
 * ledger, the galaxy and the signal-strength band word.
 */
?>
<div class="vi-cells">
    <span class="vi-c-val">
        <span class="vi-c-valtext"><?= h($card['value']) ?></span>
<?php if ($warningNote !== null): ?>
        <span class="vi-warnmark" title="<?= h($warningNote) ?>"
              role="img" aria-label="<?= h($warningNote) ?>"
              ><i class="fas fa-list-check" aria-hidden="true"></i></span>
<?php endif; ?>
    </span>
    <span class="vi-c-types"><?= h($typesText) ?></span>
    <span class="vi-c-lean"><?= $leanChip ?></span>
    <span class="vi-c-strength">
<?php if ($signalStrength === null): ?>
        <span><?= h(__('not scored')) ?></span>
<?php else: ?>
        <b><?= h($signalStrength) ?></b><?= $barSvg ?>
<?php endif; ?>
    </span>
    <span class="vi-c-rel"><?= $relevanceCell ?></span>
    <span class="vi-c-num vi-c-orgs"><b><?= h(number_format($counts['orgs'])) ?></b></span>
    <span class="vi-c-num vi-c-sig"><?php
        /*
         * A null here is a read nobody made, never a zero. Only the
         * `hot` tier produces one, and a column printing `0` for it
         * would report an absence the engine declined to look for.
         */
        if ($counts['sightings'] === null) {
            echo h(__('skipped'));
        } else {
            echo '<b>' . h(number_format($counts['sightings'])) . '</b>';
        }
    ?></span>
</div>
<div class="vi-acts">
    <button type="button" class="vi-disc" data-vi-act="toggle"
            aria-expanded="false"
            aria-label="<?= h(__('Show all signals')) ?>">
        <svg width="12" height="12" viewBox="0 0 12 12" aria-hidden="true"><path d="M3 4.5 6 8l3-3.5" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"/></svg>
    </button>
<?php if ($this->Acl->canAccess('collectionElements', 'addElementToCollection')): ?>
    <button type="button" class="vi-btn vi-btn--icon" data-vi-act="collect"
            data-vi-collect="<?= h($this->Html->url(array(
                'controller' => 'collectionElements',
                'action' => 'addElementToCollection',
                'Value',
                ValueUrlTool::encode($assessment['value']),
            ))) ?>"
            title="<?= h(__('Add to collection')) ?>"
            aria-label="<?= h(__('Add to collection')) ?>"><i
            class="fas fa-folder-plus" aria-hidden="true"></i></button>
<?php endif; ?>
<?php if ($this->Acl->canAccess('analystGraphs', 'addNodes')): ?>
    <?php // Sent to the active graph by intel-graph-actions.js ?>
    <button type="button" class="vi-btn vi-btn--icon"
            data-intel-graph-add="<?= h(json_encode(array(array(
                'type' => 'Value',
                'value' => $assessment['value'],
                'label' => $assessment['value'],
            )))) ?>"
            title="<?= h(__('Add to current graph')) ?>"
            aria-label="<?= h(__('Add to current graph')) ?>"><i
            class="misp-icon misp-icon-analyst-graph misp-simple"
            aria-hidden="true"></i></button>
<?php endif; ?>
    <?php
    /*
     * A new tab, as phase 4 opened it: the list is the work and a
     * profile is one item of it, so a reader who opened a value in
     * place would come back to a page that had forgotten their paste.
     */
    ?>
    <a class="vi-btn" target="_blank" rel="noopener"
       href="<?= h($profileUrl) ?>" data-vi-act="open"><?= h(__('Open')) ?><span
       class="vi-cardonly"> <?= h(__('intelligence')) ?></span></a>
    <button type="button" class="vi-btn vi-btn--quiet"
            data-vi-act="clear"><?= h(__('Dismiss')) ?></button>
    <?php
    /*
     * The decided row's own actions, rendered with the rest and shown
     * by the row's state. A mark and an undo: the reader needs to see
     * which of the two decisions they made, because *opened* and
     * *cleared* leave the row looking otherwise identical.
     */
    ?>
    <span class="vi-mark vi-mark--opened"><?= h(__(
        'opened in a new tab'
    )) ?></span>
    <span class="vi-mark vi-mark--cleared"><?= h(__('dismissed')) ?></span>
    <button type="button" class="vi-btn vi-btn--quiet vi-undo"
            data-vi-act="undo"><?= h(__('Undo')) ?></button>
</div>
