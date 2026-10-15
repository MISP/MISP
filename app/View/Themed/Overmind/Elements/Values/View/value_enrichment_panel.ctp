<?php
/**
 * The Overview's enrichment panel: what the modules have said about
 * this value, one row each.
 *
 * **The Overview refused anything from Enrichment for three phases**,
 * and the refusal was right on its own terms: that tab was the one
 * that read nothing from the database, so there was nothing to borrow
 * that was not a network request, and this tab renders eight panels
 * whether or not a module is up. `value_enrichment_runs` is what
 * changed — a module's last answer is now an indexed read of one
 * table, so this paints at the speed of a database read and the
 * queries, where there are any, happen after it has painted.
 *
 * **It is not emitted at all when there is nothing to show.** The page
 * frame decides that before it emits a container, so an instance that
 * has never enriched anything and declares no `auto` module has an
 * Overview identical to the one it had before this existed. The
 * panel's presence is itself the signal that something is known.
 *
 * **A summary and not the tab.** Three chips a module, a `+N` for what
 * that leaves out, and a count where the answer is a set — the shape
 * rule is `ValueEnrichmentTool::chipsFor` and it keys on the shape of
 * the response rather than on which module produced it.
 *
 * **And chips only for what the widgets do not draw.** The strip is
 * the per-type visualisation these chips were once the placeholder
 * for, so a module whose whole answer is up there loses its row: a
 * map and *country: US* under it are the same answer twice.
 *
 * When, never who: naming the analyst who ran a module would tell
 * the organisation which colleague is looking at which value.
 *
 * Lazily loaded from ValuesController::viewEnrichmentPanel.
 *
 * @var array $valueIntelligence
 * @var string $valueB64
 */
$panel = $valueIntelligence['panel'];
if (empty($panel['present'])) {
    /*
     * The endpoint's own last word on whether there is a panel. The
     * frame has already decided not to ask in the ordinary case; this
     * covers the one it cannot answer without the modules service — a
     * profile declaring `auto` for a module that turns out to be
     * disabled here.
     */
    return;
}

$baseurl = isset($baseurl) ? $baseurl : Configure::read('MISP.baseurl');
$token = isset($this->request->params['_Token']['key'])
    ? $this->request->params['_Token']['key']
    : '';

/*
 * Rows, the drawn, and the trailing line, split here rather than in
 * the model, because the split is about how a summary reads: a module
 * that could not answer is a state this page states rather than drops,
 * and an error sitting in the column of answers competes with them.
 *
 * **A module the strip drew gets no row.** Its answer is above, drawn
 * larger, in a cell that names it and dates it — and three of its
 * relations chipped underneath that is the same answer twice. So the
 * rows are what the widgets do not show: a shape that missed the five,
 * an object no renderer claims, a bare text relation.
 *
 * A module that is firing keeps its row whatever it turns out to be —
 * the browser moves it when the answer lands, because a row that
 * vanishes is easier to follow than one that was never drawn.
 */
$rows = array();
$failures = array();
$drawn = array();
foreach ($panel['modules'] as $entry) {
    if (!empty($entry['drawn'])) {
        $drawn[] = $entry['module'];
        continue;
    }
    if ($entry['pending'] !== null || $entry['state'] === 'ok') {
        $rows[] = $entry;
        continue;
    }
    $failures[] = $entry;
}

/**
 * What a module that did not answer gets said about it.
 *
 * Three phrasings and not one, because a reader acts on them
 * differently: a module with nothing to say about this value is
 * working, one that could not answer is worth an administrator's
 * attention, and an answer that has been purged is worth pressing
 * again.
 *
 * @param array $entry
 * @return string
 */
$failureLine = function (array $entry) {
    if ($entry['state'] === 'silent') {
        return sprintf(
            __('%s had nothing to say'),
            $entry['module']
        );
    }
    if ($entry['state'] === 'expired') {
        return sprintf(
            __('%s was asked, and its answer is no longer held'),
            $entry['module']
        );
    }
    return sprintf(__('%s could not answer'), $entry['module']);
};

/*
 * The sub-line counts what is on the panel rather than what is
 * eligible. *Four modules* here and *twelve eligible* on the tab are
 * both true and they answer different questions: this one is how much
 * of this row is an answer.
 *
 * **One format string with two numbers, and the browser rewrites it
 * with the same one.** The modules that fire on arrival land after
 * this is rendered, so a count fixed here is wrong within a few
 * seconds — and a server-side assertion cannot catch that, because no
 * assertion can see copy. A phrase both sides can build from the same
 * string is what keeps them from disagreeing.
 */
$subFmt = __('%1$s of %2$s answered');
$answered = count($drawn);
foreach ($rows as $entry) {
    if ($entry['pending'] === null && $entry['state'] === 'ok') {
        $answered++;
    }
}
/*
 * The drawn are counted on both sides of it: they answered, and they
 * are on the panel. Counting rows alone would make a value whose
 * every answer became a widget report *0 of 1*, with five widgets
 * above the sentence saying so.
 */
$onPanel = count($rows) + count($failures) + count($drawn);
?>
<div class="card shadow-sm mb-3 vp-panel vp-eb td-host"
     style="--vp-panel-color: var(--vp-e-accent);"
     data-vp-ebadge
     data-td-strings="<?= h($this->element('TileDrawer/strings')) ?>"
     data-vp-eb-token="<?= h($token) ?>"
     <?php
     /*
      * **The plan travels with the panel that acts on it**, so the
      * browser can act without going back for a list it was about to
      * be handed anyway.
      *
      * **Only `fire`.** The Enrichment tab sends its `fresh`
      * dispositions too, because its panes are empty until a request
      * fills them; these are not — a stored answer is drawn above,
      * out of the store, by the render that produced this attribute.
      * Asking for it again would be a round trip to redraw what is
      * already on the screen, and on an instance with the gate off it
      * would come back refused.
      *
      * Empty on any instance that has not turned auto-run on, which
      * is every instance until an administrator does — and empty is
      * how the fan-out stays off, rather than by a second flag.
      *
      * The dispositions are advisory: the model decides again when a
      * request lands, because a row can turn fresh in between.
      */
     ?>
     data-vp-eb-fire="<?= h(json_encode($panel['fire'])) ?>"
     data-vp-eb-max="5"
     data-vp-eb-fail="<?= h(__('%s could not answer')) ?>"
     data-vp-eb-silent="<?= h(__('%s had nothing to say')) ?>"
     data-vp-eb-sub="<?= h($subFmt) ?>"
     data-vp-eb-url="<?= h($baseurl . '/values/viewEnrichmentBadge/'
        . $valueB64) ?>"
     <?php
     /*
      * Where the strip is redrawn from once the modules that fired on
      * arrival have all landed. The panel's own endpoint rather than a
      * second one written to say the same thing: a widget is built
      * from every answer the store holds, so the only honest way to
      * redraw one is to ask the thing that reads the store. Only the
      * strip is taken out of what comes back — the rows below it have
      * already been updated one at a time, and replacing them would
      * undo that.
      */
     ?>
     data-vp-eb-panel="<?= h($baseurl . '/values/viewEnrichmentPanel/'
        . $valueB64) ?>">

    <?= $this->element('Values/View/value_panel_header', array(
        'panelTitle' => __('Enrichment'),
        'panelIcon' => 'fas fa-wand-magic-sparkles',
        'panelColor' => 'var(--vp-e-accent)',
        'panelSub' => '<span data-vp-eb-count>'
            . h(sprintf($subFmt, $answered, $onPanel))
            . '</span>',
    )) ?>

    <?php
    /*
     * The widgets, above the rows for the answers they do not draw:
     * the strip shows five shapes and a value can carry eight answers,
     * so the rows are what says the other three exist.
     */
    ?>
    <?= $this->element('Values/View/value_enrichment_strip', array(
        'strip' => $panel['strip'],
        'valueB64' => $valueB64,
        'baseurl' => $baseurl,
        /*
         * Carried on the strip's own markup because the browser reads
         * it off the redraw: when the modules that fired on arrival
         * land, the strip that comes back is what says which of the
         * rows it has taken over.
         */
        'drawn' => $drawn,
        /*
         * How many modules are still answering. Only ever non-zero on
         * a profile that marked something `auto` under an open gate,
         * which is the one case where what this row says is not final
         * on load — and a number that moves without saying why is
         * worse than one that took a moment.
         */
        'pending' => count($panel['fire']),
    )) ?>

    <?php
    /*
     * No body at all where the strip drew everything, rather than an
     * empty one holding its own padding open under the widgets.
     */
    ?>
    <div class="vp-eb-body<?= empty($rows) ? ' d-none' : '' ?>"
         data-vp-eb-body>
        <?php foreach ($rows as $entry): ?>
            <div class="vp-eb-row"
                 data-vp-eb-row="<?= h($entry['module']) ?>">
                <span class="vp-eb-name font-monospace"><?=
                    h($entry['module']) ?></span>
                <span class="vp-eb-slot" data-vp-eb-slot>
                    <?php if ($entry['pending'] === 'fire'): ?>
                        <span class="vp-eb-quiet">
                            <i class="fas fa-circle-notch fa-spin"
                               aria-hidden="true"></i>
                            <?= h(__('asking')) ?>
                        </span>
                    <?php elseif ($entry['pending'] === 'in_flight'): ?>
                        <?php
                        /*
                         * Somebody else's request is about to write
                         * this row, so nothing is sent: asking now
                         * would start a second query rather than wait
                         * for the first. The row says so and stays as
                         * it is until the page is opened again.
                         */
                        ?>
                        <span class="vp-eb-quiet"><?=
                            h(__('being asked now')) ?></span>
                    <?php else: ?>
                        <?= $this->element(
                            'Values/View/value_enrichment_badge',
                            array('badge' => $entry)
                        ) ?>
                    <?php endif; ?>
                </span>
            </div>
        <?php endforeach; ?>
    </div>

    <div class="vp-eb-foot<?= empty($failures) ? ' d-none' : '' ?>"
         data-vp-eb-foot>
        <?php foreach ($failures as $entry): ?>
            <span class="vp-eb-failed"><?= h($failureLine($entry)) ?></span>
        <?php endforeach; ?>
    </div>

    <?php if (!empty($panel['gate_note'])): ?>
        <?php
        /*
         * The instance's own policy, stated once and kept out of the
         * line above it: that one collects modules that could not
         * answer, and this is not about a module at all — it is about
         * what this instance permits, and a reader acts on it by
         * talking to an administrator rather than by pressing
         * anything.
         *
         * It says nothing about what this instance holds. The reason
         * the gate exists is worth remembering here: asking a third
         * party about an attacker's domain tells that third party, and
         * sometimes the attacker, that somebody is looking.
         */
        ?>
        <div class="vp-eb-policy">
            <i class="fas fa-hand" aria-hidden="true"></i>
            <?= h($panel['gate_note']) ?>
        </div>
    <?php endif; ?>
</div>
