<?php
/**
 * `/values/index` — the way in to the Value Intelligence.
 *
 * **Not an index of values, and it cannot be one.** The subject of
 * this feature is a value string rather than a row, so *all values* is
 * a `GROUP BY value1` over 3.9M attribute rows — 2M distinct — that no
 * `LIMIT` bounds (`value-index.md` §1.1). Every block on this page
 * therefore either takes its values from the reader or reads a table
 * that is genuinely value-keyed.
 *
 * The page's shape is `value-index/02b-proposal-c.html` as picked in
 * `02a-contract.md` §12 — the worklist, with A's prompt. Phase 3 wires
 * the prompt and the resolver's answers, phase 4 the rows a paste
 * becomes, phase 6 the carried-over line, phase 7 the conditions
 * strip, phase 8 the method note and phase 9 the enrichment store's
 * two numbers. The blocks that have nothing to say are absent rather
 * than drawn empty.
 *
 * **The strip is above the box and the carried-over line below it.**
 * What the strip says — whose thresholds decide the assessments —
 * is true of every answer the box will give, so a reader meets it
 * before the first one rather than after.
 *
 * **One region below the prompt, and it has one occupant.** The
 * invitation, an answer and the worklist are three things to say about
 * the same box and never two at once, so they share a container the
 * page's script can refill from `ValuesController::triage()` without
 * the paste above it moving. The clear control refills the same
 * container from the template below it, which is why the invitation
 * is an element: it is the region's empty state and the thing clear
 * puts back.
 *
 * **The tiles come before the card, not inside it.** They are
 * standing facts about the reader's own situation — what weighs a
 * record, where the bands sit, how much is checked and enriched — and
 * they are read once on arrival and not again. That makes them part of
 * the page's introduction rather than part of the box: a reader who
 * already knows them scrolls past a row, while the same facts inside
 * the card would sit between the header and the control the page
 * exists for.
 *
 * The conditions strip stays inside the card, because what it says is
 * a rule every answer the box gives was worked under.
 *
 * **The carried-over line sits outside that region**, at the foot of
 * the card, because it is the one block on the page that is not about
 * the box: a reader who pastes a list has not stopped being the reader
 * who opened something an hour ago, and a strip the script wiped on
 * every submission would be a way back that disappears the moment it
 * is wanted.
 *
 * @var array|null $resolution What `ValuesController::resolve()` made
 *                             of the box, or null on a plain load
 * @var array|null $triage The rows a pasted list became, or null
 * @var array $recent The values this reader last opened, newest first
 * @var array|null $inForce The Analyst Profile deciding this reader's
 *                          assessments, or null when none is
 * @var array $tiles The tile row's five facts, `weighs`, `bands` and
 *                   `modules` null when no profile is in force
 */
echo $this->element('genericElements/assetLoader', array(
    'css' => array('value-palette', 'value-index', 'value-index-search'),
    'js' => array('value-index', 'value-index-search'),
));

$this->set('headerTitle', __('Values'));
$this->set('headerBreadcrumb', __('Values'));
$this->set('headerDescription', __(
    'Look up a value to see what MISP knows about it, or paste a list'
    . ' to triage it.'
));
?>
<div class="vi-page">
<?php
/*
 * The tile row. A grid that wraps, and each occupant is a label, a
 * figure and a line qualifying it — so a tile added here costs one
 * line and no layout decision.
 *
 * **Three of the five describe the profile in force and are absent
 * when none is**, which is this page's rule rather than this row's: a
 * block with nothing to say is omitted, not drawn empty. A site admin
 * can disable the instance default, and a *0 signals* tile beside a
 * strip already saying assessments carry no signal strength would be a second,
 * worse way of saying it.
 */
?>
    <div class="vi-tiles">
        <?php if ($tiles['weighs'] !== null): ?>
        <?= $this->element('Values/Index/Tiles/weighs', array(
            'weighs' => $tiles['weighs'],
        )) ?>
        <?php endif; ?>
        <?php if ($tiles['bands'] !== null): ?>
        <?= $this->element('Values/Index/Tiles/bands', array(
            'bands' => $tiles['bands'],
        )) ?>
        <?php endif; ?>
        <?= $this->element('Values/Index/Tiles/warninglists', array(
            'warninglists' => $tiles['warninglists'],
        )) ?>
        <?php if ($tiles['modules'] !== null): ?>
        <?= $this->element('Values/Index/Tiles/modules', array(
            'modules' => $tiles['modules'],
        )) ?>
        <?php endif; ?>
        <?= $this->element('Values/Index/Tiles/store', array(
            'store' => $tiles['store'],
        )) ?>
    </div>
    <div class="vi-app">
        <?= $this->element('Values/Index/conditions', array(
            'inForce' => $inForce,
        )) ?>
        <?= $this->element('Values/Index/prompt') ?>
        <div class="vi-out" data-vi-out>
<?php if ($triage !== null): ?>
            <?= $this->element('Values/Index/worklist', array(
                'triage' => $triage,
            )) ?>
<?php elseif ($resolution === null): ?>
            <?= $this->element('Values/Index/invite') ?>
<?php else: ?>
            <?= $this->element('Values/Index/answer', array(
                'resolution' => $resolution,
            )) ?>
<?php endif; ?>
        </div>
<?php
/*
 * The invitation again, inert, for the clear control to put back.
 *
 * It is emitted on every load rather than only on the loads that
 * arrive with an answer: a reader who lands on the empty page, pastes
 * a list and then clears it has an answer in the region that the
 * server never rendered, and a template conditional on the *server's*
 * state would be missing for exactly that reader.
 */
?>
        <template data-vi-invite><?= $this->element('Values/Index/invite') ?></template>
        <?= $this->element('Values/Index/search') ?>
        <?= $this->element('Values/Index/recent', array(
            'recent' => $recent,
        )) ?>
    </div>
</div>
