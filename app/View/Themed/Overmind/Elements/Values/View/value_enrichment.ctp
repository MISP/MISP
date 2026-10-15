<?php
/**
 * The Enrichment tab: every module this value could be sent to, and
 * one module's answer beside it.
 *
 * **The tab has a memory since phase 11.** `value_enrichment_runs`
 * records what a module last said about a value, per organisation, so
 * a row can read *Asked 2 hours ago* and its pane can show that answer
 * without asking anybody anything. The reuse window a profile always
 * declared finally governs something (`13-auto-run.md` §4–5, D25).
 *
 * It says when, never who (D27).
 *
 * The delta against a previous run and the dismissal are still gone —
 * those were phase 12's and `28-enrichment.md` §5 is the list of what
 * came out.
 *
 * What survives is the reason `E2` was chosen: the module is the
 * navigation, and every state the tab can be in is the same object — a
 * rail row. Not asked, asked before, being asked, asking, answered,
 * answered with nothing, refused and errored are eight rows and one
 * pane.
 *
 * **Selecting a row still runs nothing**, and every module's pane is
 * still rendered up front, which is what makes picking one to read
 * incapable of querying anything.
 *
 * **What can now happen on arrival is the profile's and the
 * administrator's, together.** A module a profile marked `auto` fires
 * when this panel loads, but only where
 * `Plugin.ValueIntelligence_enrichment_auto_run` allows it — off by
 * default, so this panel behaves exactly as it did until somebody
 * turns it on. The plan rides in on `data-vp-e-auto` and is empty
 * otherwise.
 *
 * Lazily loaded from ValuesController::viewEnrichment.
 *
 * @var array $valueIntelligence
 * @var string $valueB64
 */
$profile = $valueIntelligence;
$enrichment = $profile['enrichment'];
$service = $enrichment['service'];
$modules = $enrichment['modules'];
$types = $enrichment['types'];
$canRun = !empty($enrichment['can_run']);
/*
 * What the store already holds, drawn. A module with an entry here has
 * answered before and its answer draws something, so its pane opens on
 * the drawing rather than on *has not been asked* — the state this tab
 * used to be in while the Overview drew five widgets off the same rows.
 *
 * The rows behind it are still a press away: a held answer's object
 * table is up to 1.6 MB and the widget is the half that reads at a
 * glance.
 */
$held = isset($profile['held']) ? $profile['held'] : array();

/*
 * The CSRF token the run posts back. A fresh one per fragment: tokens
 * are use-once, and the reader may run several modules.
 */
$token = isset($this->request->params['_Token']['key'])
    ? $this->request->params['_Token']['key']
    : '';

$noRun = __(
    'Running a module requires the add permission — the same one MISP'
    . ' asks for on every other enrichment surface.'
);

/*
 * The sub-line names the types because eligibility is matched on one:
 * a value is several, and a reader has to know which of them put a
 * module on the rail.
 */
$typing = isset($enrichment['typing']) ? $enrichment['typing'] : null;
$typeView = null;
$notes = '';
$bits = array();
if ($typing !== null) {
    /*
     * No occurrence, so the type is read from the value or picked by the
     * reader, and the sub-line's type becomes the control that changes it.
     */
    $groupOf = $modulesOf = array();
    foreach ($typing['choices'] as $group => $choices) {
        foreach ($choices as $choice) {
            $groupOf[$choice['type']] = $group;
            $modulesOf[$choice['type']] = $choice['modules'];
        }
    }
    $lead = $heldTypes = $kept = array();
    foreach ($types as $row) {
        if ($row['basis'] === 'held') {
            $heldTypes[] = $row['type'];
        } else {
            $lead[] = $row['type'];
        }
        if (!empty($row['kept'])) {
            $kept[] = $row['type'];
        }
    }
    $failing = array_values(array_filter(
        $lead,
        function ($type) use ($groupOf) {
            return isset($groupOf[$type]) && $groupOf[$type] === 'fails';
        }
    ));
    $typeView = array(
        'uid' => 'vp-et-' . substr(sha1(uniqid('', true)), 0, 8),
        'source' => $typing['source'],
        'read' => $typing['read'],
        'lead' => $lead,
        'held' => $heldTypes,
        'kept' => $kept,
        'failing' => $failing,
        'choices' => $typing['choices'],
        'modulesOf' => $modulesOf,
        'workflow' => !empty($typing['workflow_blocks']),
        'canRun' => $canRun,
    );
    $mono = function (array $list) {
        return implode(', ', array_map(function ($type) {
            return '<span class="vp-et-mono">' . h($type) . '</span>';
        }, $list));
    };

    $bits[] = h(__('No occurrence you can see'));
    if (!empty($types)) {
        $bits[] = $this->element(
            'Values/View/value_enrichment_type_chip',
            array('typeView' => $typeView)
        );
        if ($typeView['source'] === 'picked' && !empty($typeView['read'])) {
            $bits[] = '<button type="button" class="vp-et-back"'
                . ' data-vp-et-back>'
                . '<i class="fas fa-rotate-left" aria-hidden="true"></i>'
                . '<span class="vp-et-back-text">' . h(__n(
                    'back to the type MISP read:',
                    'back to the types MISP read:',
                    count($typeView['read'])
                )) . ' ' . $mono($typeView['read']) . '</span></button>';
        }
    } else {
        $bits[] = h(__('no type read from the value'));
    }

    if (!empty($failing)) {
        $notes .= '<div class="vp-et-note" role="note">'
            . '<i class="fas fa-triangle-exclamation" aria-hidden="true"></i>'
            . '<span>' . sprintf(
                __n(
                    '<strong>This value fails MISP’s %s check.</strong> MISP'
                        . ' would not store it as one. You can still ask;'
                        . ' expect a module to refuse it or find nothing.',
                    '<strong>This value fails MISP’s check for %s.</strong>'
                        . ' MISP would not store it as these. You can still'
                        . ' ask; expect a module to refuse it or find nothing.',
                    count($failing)
                ),
                $mono($failing)
            ) . '</span></div>';
    }
    if ($typeView['workflow']) {
        $notes .= '<div class="vp-et-note" role="note">'
            . '<i class="fas fa-ban" aria-hidden="true"></i><span>'
            . __('<strong>Runs will be refused here.</strong> This instance'
                . ' checks every enrichment query against a workflow, and'
                . ' that check needs an attribute — you hold no occurrence'
                . ' of this value. You can still look at what each module'
                . ' would be asked.')
            . '</span></div>';
    }
} else {
    $names = array();
    foreach ($types as $row) {
        $names[] = '<span class="font-monospace">'
            . h($row['type']) . '</span>';
    }
    $bits[] = sprintf(
        __n('%1$s type: %2$s', '%1$s types: %2$s', count($types)),
        h(count($types)),
        implode(', ', $names)
    );
}
if ($service['reachable']) {
    $bits[] = h(sprintf(
        __n(
            '%d module eligible',
            '%d modules eligible',
            count($modules)
        ),
        count($modules)
    ));
    $bits[] = h(sprintf(
        __('%d enabled on this instance'),
        $enrichment['enabled']
    ));
}
?>
<div class="card shadow-sm mb-3 vp-panel vp-e"
     style="--vp-panel-color: var(--vp-e-accent);"
     data-vp-enrich
     data-vp-e-value="<?= h($valueB64) ?>"
     data-vp-e-token="<?= h($token) ?>"
     data-vp-e-canrun="<?= $canRun ? '1' : '0' ?>"
     data-vp-e-n-one="<?= h(__('%s element')) ?>"
     data-vp-e-n-many="<?= h(__('%s elements')) ?>"
     data-vp-e-n-capped="<?= h(__('%1$s of %2$s')) ?>"
     data-vp-e-of="<?= h(__('%1$s of %2$s')) ?>"
     <?php
     /*
      * The merged pane's two sentences for the state this tab can now
      * open in: answers held and nothing opened. Built from a format
      * string the server hands over, like the Overview panel's count,
      * so the wording is translated once and the browser cannot
      * invent a second phrasing of it.
      */
     ?>
     data-vp-e-a-one="<?= h(__('%s answer')) ?>"
     data-vp-e-a-many="<?= h(__('%s answers')) ?>"
     data-vp-e-a-drawn-one="<?= h(__('%s answer, drawn here.')) ?>"
     data-vp-e-a-drawn-many="<?= h(__('%s answers, drawn here.')) ?>"
     <?php
     /*
      * And what a held answer nothing draws says in the merged pane.
      * It is there so the count of answers in this pane is the count
      * of answers in the store, rather than the count of the ones
      * that happened to have a renderer.
      */
     ?>
     data-vp-e-a-rows="<?= h(__('Answered in rows — open this module'
        . ' to read them.')) ?>"
     data-vp-e-a-open="<?= h(__('Open')) ?>"
     data-vp-e-a-more="<?= h(__('%s more in this module\'s own pane.')) ?>"
     <?php
     /*
      * **The plan travels with the panel that acts on it** (phase 11
      * §9), so the browser can act without going back for a list it
      * was about to be handed anyway.
      *
      * **`fresh` is in it as well as `fire`**, because §9 defines
      * `fresh` as *render it, ask nothing* and a pane cannot render
      * what was never fetched. Both go out as `mode=auto` on the same
      * endpoint, which is the whole point of that mode: it serves a
      * kept answer when there is one and asks the module when there is
      * not, so the page never has to decide which of those it is
      * about to get. A `fresh` request sends nothing outside the
      * instance and comes back in about a tenth of a second.
      *
      * Without this the tab that the Overview has already filled would
      * open on *Nothing has been queried* while the store held every
      * answer — which is exactly the state the intended flow produces.
      *
      * `in_flight` is deliberately not here: somebody else's request
      * is about to write that row, and asking for it now would start a
      * second query rather than wait for the first.
      *
      * Empty on any instance that has not turned auto-run on, which is
      * every instance until an administrator does — and empty is how
      * the fan-out stays off, rather than by a second flag.
      *
      * The dispositions are advisory: `enrichmentRun()` decides again
      * when a request lands, because a row can turn fresh in between.
      */
     $autoFire = array();
     foreach ($enrichment['profile']['auto'] as $one) {
         if ($one['disposition'] !== 'fire'
             && $one['disposition'] !== 'fresh'
         ) {
             continue;
         }
         $autoFire[] = array(
             'module' => $one['module'],
             'type' => $one['type'],
         );
     }
     ?>
     data-vp-e-auto="<?= h(json_encode($autoFire)) ?>"
     data-vp-e-auto-max="5"
     <?php if ($typeView !== null): ?>
     data-vp-et
     data-vp-et-source="<?= h($typeView['source']) ?>"
     data-vp-et-read="<?= h(json_encode($typeView['read'])) ?>"
     data-vp-et-lead="<?= h(json_encode($typeView['lead'])) ?>"
     data-vp-et-failing="<?= empty($typeView['failing']) ? '0' : '1' ?>"
     <?php endif; ?>
     data-vp-e-url="<?= h($baseurl . '/values/viewEnrichmentRun/'
        . $valueB64) ?>">

    <?= $this->element('Values/View/value_panel_header', array(
        'panelTitle' => __('Enrichment'),
        'panelIcon' => 'fas fa-wand-magic-sparkles',
        'panelColor' => 'var(--vp-e-accent)',
        'panelSub' => implode(' &middot; ', $bits),
        'panelNotes' => $notes === '' ? null : $notes,
    )) ?>

    <?php
    /*
     * Above the branch on purpose. A profile naming a module this
     * instance has turned off is precisely the case with no rail to
     * hang the condition on, and a reader told "no enabled module
     * accepts this value's types" while their own profile names one
     * has been quietly lied to.
     */
    ?>
    <?= $this->element('Values/View/value_enrichment_profile', array(
        'enrichment' => $enrichment,
    )) ?>

    <?php if (!$service['reachable']): ?>

        <?php
        /*
         * The service, not the modules. A reader who is told "no
         * modules" when the truth is "nobody answered the door" will
         * conclude this instance enriches nothing, which is a
         * different and wrong fact about their own deployment.
         */
        ?>
        <div class="vp-empty p-4">
            <div class="fw-semibold mb-1">
                <?= h(__('The enrichment service did not answer.')) ?>
            </div>
            <div class="small text-muted">
                <?= h(__(
                    'This says nothing about which modules exist or'
                    . ' whether they would have anything to report —'
                    . ' the list itself is what could not be read.'
                    . ' Nothing has been sent anywhere.'
                )) ?>
            </div>
            <?php if (!empty($service['error'])): ?>
                <div class="small text-muted mt-2 font-monospace">
                    <?= h($service['error']) ?>
                </div>
            <?php endif; ?>
        </div>

    <?php elseif (empty($types) && $typeView !== null
        && array_filter($typeView['choices'])
    ): ?>

        <div class="vp-et-inline">
            <div class="vp-et-inline-title">
                <?= h(__('No type read from this value')) ?>
            </div>
            <div class="vp-et-inline-prose">
                <?= h(__(
                    'Modules are matched on an attribute type, and MISP could'
                    . ' not read one from this value. Pick the type you mean:'
                    . ' that lists the modules taking it, and sends nothing.'
                )) ?>
            </div>
            <?= $this->element(
                'Values/View/value_enrichment_type_picker',
                array('typeView' => $typeView, 'inline' => true)
            ) ?>
        </div>

    <?php elseif (empty($types)): ?>

        <?php
        // No occurrence to take a type from, and the value's shape gave none.
        ?>
        <div class="vp-empty p-4">
            <div class="fw-semibold mb-1">
                <?= h(__('No type to match modules on.')) ?>
            </div>
            <div class="small text-muted">
                <?= h(__(
                    'Enrichment modules accept attribute types. You hold'
                    . ' no occurrence of this value to take one from, and'
                    . ' MISP could not read one from the value itself.'
                    . ' Nothing has been sent anywhere.'
                )) ?>
            </div>
        </div>

    <?php elseif (empty($modules)): ?>

        <div class="vp-empty p-4">
            <div class="fw-semibold mb-1">
                <?= h(__(
                    'No enabled module accepts any of this value\'s'
                    . ' types.'
                )) ?>
            </div>
            <div class="small text-muted">
                <?= h(sprintf(
                    __n(
                        'One module is enabled on this instance and it'
                        . ' does not take these types.',
                        '%d modules are enabled on this instance and'
                        . ' none of them takes these types.',
                        $enrichment['enabled']
                    ),
                    $enrichment['enabled']
                )) ?>
            </div>
        </div>

    <?php else: ?>

        <div class="vp-e-split">

            <?= $this->element('Values/View/value_enrichment_rail', array(
                'enrichment' => $enrichment,
                'canRun' => $canRun,
                'noRun' => $noRun,
                'heldCount' => count($held),
            )) ?>

            <div class="vp-e-pane">

                <?php
                /*
                 * The resting pane, shown until a row is picked. It is
                 * the tab's opening claim and the reason nothing has
                 * been queried is stated here rather than implied by
                 * an empty column.
                 *
                 * **It is not the opening claim where answers are
                 * held.** *Nothing has been queried* is false the
                 * moment the store holds one, and the Overview has
                 * been drawing those answers since phase 11 — so the
                 * merged pane opens instead, with what is held already
                 * in it. Decided server-side rather than switched by
                 * the browser, so there is no cold pane to flash.
                 */
                ?>
                <div<?= empty($held) ? '' : ' class="d-none"' ?>
                     data-vp-e-pane="__none">
                    <div class="vp-e-cold vp-e-cold-solo">
                        <div class="vp-e-cold-title">
                            <?= h(__('Nothing has been queried.')) ?>
                        </div>
                        <div class="vp-e-cold-prose">
                            <?= h(__(
                                'This page has sent nothing to any'
                                . ' module. Picking one below shows'
                                . ' what it would be asked; running it'
                                . ' sends this value to whoever'
                                . ' operates it, which spends the'
                                . ' instance\'s quota and tells them'
                                . ' somebody is looking.'
                            )) ?>
                        </div>
                        <div class="vp-e-cold-prose mt-2">
                            <?php
                            /*
                             * What this said until phase 11 — *nothing
                             * a module returns is stored* — stopped
                             * being true when the run store landed,
                             * and the brief beside it was corrected
                             * while this was missed.
                             */
                            ?>
                            <?= h(__(
                                'An answer is kept for your'
                                . ' organisation, so opening this'
                                . ' value again does not ask the'
                                . ' module again.'
                            )) ?>
                        </div>
                    </div>
                </div>

                <?php
                /*
                 * The merged pane — `E2`'s one addition to the
                 * direction it came from. The rail costs the reader
                 * cross-module reading and this buys it back.
                 *
                 * Filled on the client by cloning what the answered
                 * panes already hold, so it costs no request and
                 * cannot disagree with them.
                 *
                 * **Including the answers nobody opened.** Every held
                 * answer is drawn into its own pane when this tab
                 * renders, so the merge has something to clone before
                 * a reader has pressed anything — which is what makes
                 * this the pane the tab opens on where the store holds
                 * something. What it merges is still exactly what the
                 * panes hold: drawings for everything held, and rows
                 * as well for whatever has been opened.
                 */
                ?>
                <div<?= empty($held) ? ' class="d-none"' : '' ?>
                     data-vp-e-pane="__all">
                    <?php
                    /*
                     * The merged pane wears a result's head, because
                     * that is what it is: the same rows under one
                     * claim. Anything else would have the reader
                     * learning a second layout for the same content.
                     */
                    ?>
                    <div class="vp-e-res-head">
                        <i class="fas fa-layer-group vp-e-mark
                                  vp-e-mark-quiet" aria-hidden="true"></i>
                        <div class="vp-e-res-headtext">
                            <div class="vp-e-cold-title" data-vp-e-allhead>
                                <?= h(__(
                                    'Nothing has been opened here yet.'
                                )) ?>
                            </div>
                            <div class="vp-e-cold-prose mb-0">
                                <?php
                                /*
                                 * Both sentences this carried stopped
                                 * being true in phase 11: answers are
                                 * stored now, and an answer from last
                                 * time is exactly what a module row
                                 * may already be holding.
                                 */
                                ?>
                                <?= h(__(
                                    'Every answer your organisation'
                                    . ' holds for this value, drawn.'
                                    . ' Opening a module adds the rows'
                                    . ' its drawing was made from,'
                                    . ' without asking anybody'
                                    . ' anything.'
                                )) ?>
                            </div>
                        </div>
                    </div>
                    <div data-vp-e-allbody></div>
                </div>

                <?php
                /*
                 * One pane per module, rendered up front and empty.
                 * The run fills it in place; picking between them is a
                 * class change and never a request, which is the
                 * promise the tab is built to keep.
                 */
                ?>
                <?php foreach ($modules as $module): ?>
                    <?php
                    /*
                     * `data-vp-e-held` marks a pane holding an answer,
                     * whether or not anything draws it. The merged
                     * pane counts those panes, and the tab's badge
                     * counts rows in the store — so a module answering
                     * in bare text has to be one of the things merged,
                     * or the two numbers would disagree by it.
                     */
                    ?>
                    <div class="d-none"
                         <?= isset($held[$module['name']])
                            ? 'data-vp-e-held' : '' ?>
                         data-vp-e-pane="<?= h($module['name']) ?>">
                        <div data-vp-e-slot>
                            <?php
                            /*
                             * What this module last said, drawn, above
                             * the brief that says when it said it and
                             * how to get the rows.
                             *
                             * **Inside the slot**, which is what a run
                             * replaces: pressing *Show what came back*
                             * swaps the whole thing for the full
                             * result, so the widget cannot end up
                             * drawn twice or drawn from two answers.
                             */
                            ?>
                            <?php if (!empty(
                                $held[$module['name']]['shapes']
                            )): ?>
                                <div class="vp-e-heldshapes"
                                     data-vp-e-heldshapes>
                                    <?php foreach (
                                        $held[$module['name']]['shapes']
                                        as $shape
                                    ): ?>
                                        <?= $this->element(
                                            'Values/View/'
                                            . 'value_enrichment_shape',
                                            array('shape' => $shape)
                                        ) ?>
                                    <?php endforeach; ?>
                                </div>
                            <?php endif; ?>
                            <?= $this->element(
                                'Values/View/value_enrichment_brief',
                                array(
                                    'module' => $module,
                                    'service' => $service,
                                    'canRun' => $canRun,
                                    'noRun' => $noRun,
                                )
                            ) ?>
                        </div>
                    </div>
                <?php endforeach; ?>

            </div>

        </div>

    <?php endif; ?>

</div>
