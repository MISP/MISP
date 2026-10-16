<?php
/**
 * What one module would be asked, before anybody asks it.
 *
 * The pane a module shows until it is run, and the argument for the
 * press: what leaves the instance, what it is asked about, and what
 * happens to the answer. Phase 12 drew this as a cost estimate in
 * quota and credits; **no such metadata exists** — module
 * introspection carries a name, its accepted types, a description, its
 * kinds and its config keys, and nothing about rate limits or money —
 * so this states what is actually knowable instead of pricing a run
 * it would have to invent a number for.
 *
 * A plain partial, not an endpoint.
 *
 * @var array $module   One catalogue row
 * @var array $service
 * @var bool $canRun
 * @var string $noRun
 */
$kinds = implode(', ', $module['kinds']);
?>
<div class="vp-e-cold">

    <?php
    /*
     * Two children and only two: `.vp-e-cold` is a main column and an
     * aside, and a grid handed five children flows them alternately
     * into both — which put the description opposite the title and
     * the ledger opposite the note.
     */
    ?>
    <div class="vp-e-cold-main">

    <?php
    /*
     * Phase 11. This pane used to be able to say only one thing —
     * *has not been asked* — because nothing recorded that anything
     * ever had. Since `value_enrichment_runs` it can be wrong about
     * that, and a rail row reading *Asked 2 hours ago* against a pane
     * reading *has not been asked* is the page contradicting itself.
     *
     * So there are three openings: never asked, being asked by
     * somebody else right now, and asked before. The third is the one
     * that carries a second control, because the reader wants the
     * answer more often than they want another query.
     *
     * **When, never who** (D27).
     */
    $stored = isset($module['stored']) ? $module['stored'] : null;
    $inFlight = $stored !== null && !$stored['held'];
    ?>

    <div class="vp-e-cold-title">
        <?php if ($inFlight): ?>
            <?= h(sprintf(
                __('%s is being asked now.'),
                $module['name']
            )) ?>
        <?php elseif ($stored !== null): ?>
            <?= h(sprintf(__('%s was asked'), $module['name'])) ?>
            <?= $this->element(
                'Values/View/value_enrichment_age',
                array('askedAge' => $stored['age'])
            ) ?><?= h(__('.')) ?>
        <?php else: ?>
            <?= h(sprintf(
                __('%s has not been asked.'),
                $module['name']
            )) ?>
        <?php endif; ?>
    </div>

    <?php if (!empty($module['description'])): ?>
        <div class="vp-e-cold-prose">
            <?= h($module['description']) ?>
        </div>
    <?php endif; ?>

    <?php if ($inFlight): ?>
        <div class="vp-e-cold-prose mt-3">
            <?= h(__(
                'Somebody in your organisation is running this right'
                . ' now. Its answer will be kept and shown here.'
            )) ?>
        </div>
    <?php elseif ($stored !== null): ?>
        <div class="vp-e-cold-prose mt-3">
            <?= h(sprintf(
                __(
                    'It was asked as %s and the answer was kept. Show'
                    . ' it without asking anybody anything, or run the'
                    . ' module again for a fresh one.'
                ),
                $stored['type']
            )) ?>
        </div>
    <?php else: ?>
        <div class="vp-e-cold-prose mt-3">
            <?= h(__(
                'Nothing is written to MISP. The answer is kept for'
                . ' your organisation so that opening this value again'
                . ' does not ask the module again.'
            )) ?>
        </div>
    <?php endif; ?>

    <div class="mt-3">
        <?php if ($stored !== null && !$inFlight): ?>
            <?= $this->element(
                'Values/View/value_enrichment_button',
                array(
                    'module' => $module,
                    'canRun' => $canRun,
                    'noRun' => $noRun,
                    'label' => __('Show the rows'),
                    'mode' => 'stored',
                    'variant' => 'secondary',
                    'runType' => $stored['type'],
                )
            ) ?>
        <?php endif; ?>
        <?= $this->element('Values/View/value_enrichment_button', array(
            'module' => $module,
            'canRun' => $canRun,
            'noRun' => $noRun,
            'label' => $stored === null
                ? sprintf(__('Run %s'), $module['name'])
                : __('Ask again'),
        )) ?>
    </div>

    </div>

    <div class="vp-e-cold-ledger">

        <div class="vp-e-ledger-row">
            <span class="vp-e-ledger-n"><?= h(__('Sends')) ?></span>
            <span>
                <?php
                /*
                 * The two formats differ in what leaves, and the
                 * difference is worth stating plainly: one sends the
                 * value, the other sends the attribute row it sits in
                 * — which carries its category, its comment and its
                 * IDS flag along with it.
                 */
                ?>
                <?= $module['format'] === 'misp_standard'
                    ? h(__(
                        'the attribute row this value sits in, as'
                        . ' MISP stores it'
                    ))
                    : h(__('this value and its type')) ?>
                <span class="text-muted">
                    (<span class="font-monospace"><?= h(
                        $module['format']
                    ) ?></span>)
                </span>
            </span>
        </div>

        <div class="vp-e-ledger-row">
            <span class="vp-e-ledger-n"><?= h(__('As')) ?></span>
            <span class="font-monospace"><?= h($module['type']) ?></span>
        </div>

        <div class="vp-e-ledger-row">
            <span class="vp-e-ledger-n"><?= h(__('Kind')) ?></span>
            <span><?= h($kinds) ?></span>
        </div>

        <?php if (!empty($module['config'])): ?>
            <div class="vp-e-ledger-row">
                <span class="vp-e-ledger-n">
                    <?= h(__('Settings')) ?>
                </span>
                <span>
                    <?= h(sprintf(
                        __n(
                            'declares %d setting',
                            'declares %d settings',
                            count($module['config'])
                        ),
                        count($module['config'])
                    )) ?>
                    <span class="text-muted">
                        <?php
                        /*
                         * Stated, never judged. Nothing distinguishes
                         * a key a module needs from one it merely
                         * accepts: `whois` fails without two of its
                         * three, `mmdb_lookup` works without any of
                         * its four. So the row reports what is
                         * declared and the run reports what happened.
                         */
                        ?>
                        &mdash; <?= h(__(
                            'whether any are required is something'
                            . ' only the run can say'
                        )) ?>
                    </span>
                </span>
            </div>
        <?php endif; ?>

        <div class="vp-e-ledger-row">
            <span class="vp-e-ledger-n"><?= h(__('Gives up after')) ?></span>
            <span><?= h(sprintf(
                __('%d s'),
                $service['timeout']
            )) ?></span>
        </div>

    </div>

</div>
