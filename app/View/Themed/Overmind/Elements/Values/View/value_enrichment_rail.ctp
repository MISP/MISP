<?php
/**
 * The rail: one row per module eligible for this value, plus the
 * merged row above them and the tray below.
 *
 * **A module is one row however many of the value's types put it
 * there.** `8.8.8.8` is four types and `circl_passivedns` accepts
 * three of them; that is one module, and the row names the type a run
 * would use rather than repeating itself three times.
 *
 * **No grouping, because grouping needs memory.** Phase 12 sorted the
 * rail into *ran / not in the last run / never run*, which are three
 * claims about history, and history is what a stateless tab does not
 * have. The rows sort by name — a stable order a reader can learn,
 * rather than one that reshuffles as they work.
 *
 * The state a row *does* carry is this visit's: not asked, asking,
 * answered, answered with nothing, timed out, errored, refused. Set by
 * the run, on the client, against markup this element sent.
 *
 * **Since phase 7 the boxes can arrive ticked.** The reader's Analyst
 * Profile names modules per attribute type, and the ones it names for
 * this value's types are selected on arrival — selected, not run.
 * Everything a press does is unchanged; what changes is that the press
 * defaults to the analyst's own list instead of to nothing.
 *
 * A plain partial, not an endpoint.
 *
 * @var array $enrichment
 * @var bool $canRun
 * @var string $noRun
 * @var int $heldCount Answers the store already holds, drawn in the
 *                     merged pane — which is the row this rail opens
 *                     on when there are any
 */
$modules = $enrichment['modules'];
$service = $enrichment['service'];

/*
 * The profile's selection, as a lookup: module name => the type a run
 * would use. The type is the profile's rather than the row's default
 * wherever the module accepts it, because filing `virustotal` under
 * `ip-dst` is a statement about which question to ask.
 */
$picked = array();
if (!empty($enrichment['profile']['selected'])) {
    foreach ($enrichment['profile']['selected'] as $entry) {
        $picked[$entry['name']] = $entry['type'];
    }
}

/*
 * Whether a module answers from inside, on the box that selects it.
 *
 * **Two states here, though `ModuleLocality` has three.** Its third —
 * *nobody has classified this module* — is a real distinction the
 * per-module chip keeps, but a flag cannot: it would understate the
 * presumption the whole design runs on, which is that an enrichment
 * module enriches from somewhere else unless it is known not to. So a
 * box reads `0` only for a module known to answer from inside.
 *
 * The tray used to total these into a line above the run button. That
 * line went in 2026-09-21: the panel header already says how many of
 * the selection would leave the instance.
 */
$flags = array();
foreach ($modules as $module) {
    $flags[$module['name']] = isset($module['locality'])
        && $module['locality'] === 'local' ? '0' : '1';
}
$chosen = count($picked);
?>
<div class="vp-e-rail">

    <?php
    /*
     * Select all, and the count beside it. Phase 12 put this here to
     * price a batch before committing to it; the price it quoted was
     * quota and third-party exposure, and neither has a source. What
     * a selection can still be honestly told is **how many modules it
     * is**, which is also how many separate queries the press makes —
     * a run is one module, so `Run 3 selected` is three requests, one
     * after another.
     */
    ?>
    <div class="vp-e-railhead">
        <label class="vp-e-selall">
            <input type="checkbox" class="form-check-input"
                   data-vp-e-select-all
                   <?= $chosen > 0 && $chosen === count($modules)
                        ? 'checked' : '' ?>
                   <?= $canRun ? '' : 'disabled' ?>>
            <span><?= h(__('Select all')) ?></span>
        </label>
        <span class="vp-e-railhead-n">
            <span data-vp-e-picked><?= h($chosen) ?></span>
            <?= h(sprintf(__('of %d selected'), count($modules))) ?>
        </span>
    </div>

    <div class="vp-e-railscroll">

        <?php
        /*
         * `All results` — the one addition `E2` makes to the direction
         * it came from. The rail costs the reader cross-module
         * reading, and this row buys it back by putting every answer
         * in one pane. It is filled on the client from the runs made
         * this visit, because that is the only span a page with no
         * memory can merge over.
         */
        ?>
        <?php $heldCount = isset($heldCount) ? (int)$heldCount : 0; ?>
        <div class="vp-e-railrow vp-e-railrow-all<?=
             $heldCount > 0 ? ' vp-e-railrow-on' : '' ?>"
             data-vp-e-row="__all">
            <button type="button"
                    class="vp-e-railbody"
                    data-vp-e-pick="__all"
                    aria-pressed="<?= $heldCount > 0
                        ? 'true' : 'false' ?>">
                <span class="vp-e-railrow-name">
                    <?= h(__('All results')) ?>
                </span>
                <span class="vp-e-railrow-sub" data-vp-e-allsub>
                    <?php
                    /*
                     * *Nothing run yet* was true of a tab with no
                     * memory. Where the store holds answers this row
                     * is the one the tab opens on, and it says how
                     * many are in it.
                     */
                    ?>
                    <?= h($heldCount > 0
                        ? sprintf(
                            __n('%s answer', '%s answers', $heldCount),
                            number_format($heldCount)
                        )
                        : __('Nothing run yet')) ?>
                </span>
            </button>
        </div>

        <div class="vp-e-railgroup">
            <?= h(sprintf(
                __n('%d module', '%d modules', count($modules)),
                count($modules)
            )) ?>
        </div>

        <?php foreach ($modules as $module): ?>
            <?php
            /*
             * The sub-line is the type the run would use and the
             * kinds the module answers as. Not a cost: no cost
             * metadata exists, and a chip that implied one would be
             * inventing it.
             */
            $types = array_keys($module['types']);
            $extra = count($types) - 1;
            $mine = isset($picked[$module['name']]);
            $runType = $mine
                ? $picked[$module['name']]
                : $module['type'];
            ?>
            <div class="vp-e-railrow" data-vp-e-row="<?= h($module['name']) ?>">

                <label class="vp-e-selbox">
                    <input type="checkbox" class="form-check-input"
                           data-vp-e-select="<?= h($module['name']) ?>"
                           data-vp-e-seltype="<?= h($runType) ?>"
                           data-vp-e-external="<?=
                                h($flags[$module['name']]) ?>"
                           <?= $mine ? 'checked' : '' ?>
                           <?= $canRun ? '' : 'disabled' ?>
                           aria-label="<?= h(sprintf(
                                __('Select %s'),
                                $module['name']
                           )) ?>">
                </label>

                <button type="button"
                        class="vp-e-railbody"
                        data-vp-e-pick="<?= h($module['name']) ?>"
                        aria-pressed="false">

                    <span class="vp-e-railrow-name">
                        <span class="vp-e-dot vp-e-dot-none"
                              data-vp-e-dot></span>
                        <?= h($module['name']) ?>
                    </span>

                    <span class="vp-e-railrow-sub">
                        <span class="font-monospace"><?= h(
                            $runType
                        ) ?></span>
                        <?php if ($extra > 0): ?>
                            <span class="text-muted"
                                  title="<?= h(sprintf(
                                    __('Also accepts %s'),
                                    implode(', ', array_slice($types, 1))
                                  )) ?>">
                                <?= h(sprintf(__('+%d'), $extra)) ?>
                            </span>
                        <?php endif; ?>
                        <span class="vp-e-kind"><?= h(implode(
                            '+',
                            $module['kinds']
                        )) ?></span>
                        <?php
                        /*
                         * Why this box is ticked. Without it a reader
                         * who has never opened the profile editor
                         * finds a selection they did not make and no
                         * way to learn where it came from.
                         */
                        ?>
                        <?php if ($mine): ?>
                            <span class="vp-e-mine"
                                  title="<?= h(__(
                                    'Named by your Analyst Profile for'
                                    . ' this type. Selected, not run.'
                                  )) ?>">
                                <?= h(__('profile')) ?>
                            </span>
                        <?php endif; ?>
                        <?php
                        /*
                         * How much came back, once something has.
                         * `Answered` is the same word for two
                         * elements and for two hundred, and comparing
                         * modules at a glance is the rail's whole
                         * job.
                         */
                        ?>
                        <span class="vp-e-railrow-n d-none"
                              data-vp-e-count></span>
                    </span>

                    <?php
                    /*
                     * The memory, phase 11 (D25). A module somebody in
                     * this organisation already asked says when rather
                     * than *Not asked*, whether or not any profile
                     * declared it — the store is the tab's, not
                     * auto-run's.
                     *
                     * **When, never who** (D27).
                     *
                     * A row still being asked by somebody else's
                     * request says so instead: it is neither an answer
                     * nor an absence, and drawing it as either would
                     * have the reader press a button that is about to
                     * be answered anyway.
                     */
                    $stored = isset($module['stored'])
                        ? $module['stored']
                        : null;
                    $inFlight = $stored !== null
                        && !$stored['held'];
                    ?>
                    <?php if ($inFlight): ?>
                        <span class="vp-e-status vp-e-status-none"
                              data-vp-e-state><?= h(__(
                            'Being asked'
                        )) ?></span>
                    <?php elseif ($stored !== null): ?>
                        <span class="vp-e-status vp-e-status-none"
                              data-vp-e-state
                              title="<?= h(sprintf(
                                __('Asked as %s. Opening it shows what'
                                    . ' came back; running it asks'
                                    . ' again.'),
                                $stored['type']
                              )) ?>"><?= h(__('Asked')) ?>
                            <?= $this->element(
                                'Values/View/value_enrichment_age',
                                array('askedAge' => $stored['age'])
                            ) ?></span>
                    <?php else: ?>
                        <span class="vp-e-status vp-e-status-none"
                              data-vp-e-state><?= h(__(
                            'Not asked'
                        )) ?></span>
                    <?php endif; ?>

                </button>

            </div>
        <?php endforeach; ?>

    </div>

    <div class="vp-e-tray">

        <?php
        /*
         * **The cost line is gone, 2026-09-21.** Three phrasings of
         * how many queries a selection would send sat above this
         * button, and the header already carries the same count as
         * *N of these would leave the instance* — on a rail whose
         * every row names its own locality. The button says what it
         * will do and the row above it is quieter for not saying it
         * a third time.
         */
        ?>
<?php
        /*
         * Disabled on arrival whoever is reading, unless the reader's
         * own profile has already selected something and they may run
         * — which is the one case where a press is meaningful before
         * any click. The client keeps it in step from there.
         */
        ?>
        <button type="button"
                class="btn btn-sm mt-2 d-inline-flex align-items-center
                       gap-1 <?= $canRun
                    ? 'btn-outline-primary'
                    : 'disabled btn-outline-secondary' ?>"
                <?= ($canRun && $chosen > 0) ? '' : 'disabled' ?>
                <?= $canRun ? '' : 'title="' . h($noRun) . '"' ?>
                data-vp-e-run-selected>
            <i class="fas fa-play" data-vp-e-icon></i>
            <span data-vp-e-label>
                <?= h(__('Run')) ?>
                <span data-vp-e-runcount><?= h($chosen) ?></span>
                <?= h(__('selected')) ?>
            </span>
        </button>

        <div class="vp-e-svc mt-2">
            <i class="fas fa-plug"></i>
            <?= h(sprintf(
                __('Service answered in %d ms'),
                $service['took']
            )) ?>
            &middot;
            <?= h(sprintf(
                __('%d s limit per module'),
                $service['timeout']
            )) ?>
        </div>
    </div>

</div>
