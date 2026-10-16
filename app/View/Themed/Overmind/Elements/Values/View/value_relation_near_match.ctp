<?php
/**
 * Section two: values that are close to this one without being it.
 *
 * The sentence this whole section exists to prevent a reader from
 * assuming is *these two values are the same*. They are not, and the
 * panel says so above the rows rather than trusting a dashed border to
 * carry the argument.
 *
 * Four engine states appear here and all four are different:
 *
 *   active           the engine runs for this type and found rows.
 *   cannot run       MISP ships the engine and it applies to this
 *                    value, but the extension behind it is not loaded
 *                    here. A fact about the instance, not the value,
 *                    and the only one of the four somebody can fix.
 *   not applicable   the engine exists and runs, but not on a value of
 *                    this type. Nothing is missing, nothing is hidden.
 *   no engine        MISP has no such engine at all. Not empty, not
 *                    inapplicable — absent, and still named so the gap
 *                    is visible rather than quietly dropped.
 *
 * The first two get a block, because each has something to report. The
 * last two are one fact apiece and get one line apiece — see
 * `$engineLine`. Before that they spent ~310px of a ~760px section
 * explaining, at length, that they had done nothing.
 *
 * Nothing here reads a provenance column, because there is none: the
 * correlation table stores `value`, two event ids, two attribute ids,
 * org and distribution, and exact matches and CIDR containment are
 * written into it together. Every row below is re-derived at render
 * time, and says so.
 *
 * Lazily loaded from ValuesController::viewRelationNearMatch.
 *
 * @var array $valueIntelligence
 * @var string $valueB64
 */
$profile = $valueIntelligence;
$near = $profile['relationships']['near'];
$view = $this;

/*
 * The type the engines are asked about. An unknown value has no
 * attribute anywhere on the instance and so
 * has no type for an engine to decline — which is a fourth sentence
 * again, and not the same as "the engine does not apply".
 */
$primaryType = null;
if (!empty($profile['types'])) {
    $primaryType = $profile['types'][0]['type'];
}

$engines = array();
foreach ($near['engines'] as $engine) {
    $engines[$engine['id']] = $engine;
}

/**
 * A permutation class, in words a reader has not had to learn.
 *
 * The model carries the class as a key and stops there, because the
 * generator behind it is a MISP-free tool with no translator; the
 * wording is a view decision and lives where `__()` can find it.
 *
 * @param string $class
 * @return string
 */
$permutationLabel = function ($class) {
    $labels = array(
        'omission' => __('Character dropped'),
        'repetition' => __('Character doubled'),
        'transposition' => __('Neighbours swapped'),
        'replacement' => __('Adjacent key'),
        'insertion' => __('Adjacent key inserted'),
        'vowel_swap' => __('Vowel exchanged'),
        'homoglyph' => __('Look-alike character'),
        'bitsquat' => __('One bit flipped'),
        'hyphenation' => __('Hyphen inserted'),
        'subdomain' => __('Dot inserted'),
        'addition' => __('Character appended'),
        'tld_swap' => __('Different ending'),
    );
    return isset($labels[$class]) ? $labels[$class] : $class;
};

/*
 * **Whether `Similarity >=` is offered at all**, and it is not a
 * cosmetic question. `rowMatchesMinimums` in `value-intelligence.js` drops
 * a row that carries no number under a key the reader has cut on —
 * deliberately, because *"I do not know"* is not evidence — so a
 * typosquat row, whose closeness is a permutation class and not a
 * percentage, would vanish the moment the control moved off zero. A
 * control that deletes rows it cannot rank is worse than no control,
 * so it appears only when every row on screen carries a number.
 *
 * In practice the two never coexist: the numeric engines want an
 * address or a hash and this one wants a name. The check is written
 * against the general case anyway, because the cost of being wrong
 * here is silent.
 */
$scaledRows = 0;
$unscaledRows = 0;
foreach ($near['engines'] as $engine) {
    if (empty($engine['rows'])) {
        continue;
    }
    if ($engine['id'] === 'typosquat') {
        $unscaledRows += count($engine['rows']);
    } else {
        $scaledRows += count($engine['rows']);
    }
}
$offerSimilarity = $scaledRows > 0 && $unscaledRows === 0;

/**
 * @param array $row
 * @return string
 */
$distributionBadge = function ($row) use ($view) {
    return $view->element(
        'genericElementsBS5/Badges/distribution',
        array('distribution' => (int)$row['distribution'], 'full' => false)
    );
};

/**
 * Closeness as a share of whatever the row's scale is.
 *
 * A prefix over the address width for a network block — 32 bits for
 * IPv4 and 128 for IPv6 — and the score itself for ssdeep, which is
 * already a percentage. `Similarity ≥` filters on this number, so the control
 * and the bar cannot disagree whichever engine wrote the row.
 *
 * @param array $row
 * @return int
 */
$closeness = function ($row) {
    return (int)round(((int)$row['prefix'] / (int)$row['width']) * 100);
};

/**
 * A matched value short enough for the column and still readable as
 * itself.
 *
 * `.vp-rel-cell` clips at 18rem and puts the ellipsis at the end, which
 * is right for a network block and useless for an ssdeep hash: the
 * hashes in a family share a prefix — sharing one is what makes them a
 * family — so every row clipped to the same visible string. The middle
 * goes instead, and the whole value is on the cell's title either way.
 *
 * @param string $label A CIDR block, or an ssdeep hash
 * @return string
 */
$shorten = function ($label) {
    if (strlen($label) <= 40) {
        return $label;
    }
    return substr($label, 0, 24) . '…' . substr($label, -12);
};

ob_start();
?>
    <?php if ($offerSimilarity): ?>
        <label class="small text-muted" for="vp-rel-similarity">
            <?= __('Similarity') ?> &ge;
        </label>
        <div class="input-group input-group-sm" style="width: 6.5rem">
            <input type="number" class="form-control" id="vp-rel-similarity"
                   min="0" max="100" step="1" value="0"
                   data-vp-filter-min="closeness">
            <span class="input-group-text">%</span>
        </div>
    <?php endif; ?>
<?php
$headerExtra = ob_get_clean();
if (!$offerSimilarity) {
    $headerExtra = null;
}
?>
<div class="card shadow-sm mb-3 vp-panel vp-rel-k-near"
     style="--vp-panel-color: var(--vp-rel-near);"
     data-vp-list
     data-vp-rel-summary="near"
     data-vp-rel-count="<?= h(number_format($near['matches'])) ?>"
     <?php if (empty($near['engines'])): ?>
         data-vp-rel-note="<?= h(__('no engine applies')) ?>"
     <?php endif; ?>>

    <?php
    ob_start();
    ?>
        <span class="vp-rel-tag me-1">
            <i class="fas fa-code-compare"></i><?= h(__('Near-match')) ?>
        </span>
        <?php if (empty($near['engines'])): ?>
            <?= h(__('No engine has been asked')) ?>
        <?php else: ?>
            <?= h(sprintf(
                __('%1$s from %2$s'),
                __n('%d match', '%d matches', $near['matches'],
                    $near['matches']),
                __n('%d engine', '%d engines', $near['engines_active'],
                    $near['engines_active'])
            )) ?>
            &nbsp;·&nbsp;
            <?php
            /*
             * *Not running* rather than *does not apply*: the idle
             * count is the sum of three different states — an engine
             * that declines this type, one MISP ships but cannot load,
             * and one that does not exist at all — and only the first
             * of them "does not apply". The body draws the distinction
             * per engine; the header must not undo it in a summary.
             */
            ?>
            <?= h(__n(
                '%d engine is not running here',
                '%d engines are not running here',
                $near['engines_idle'],
                $near['engines_idle']
            )) ?>
        <?php endif; ?>
        &nbsp;·&nbsp;
        <span class="vp-rel-prov"><i class="fas fa-gauge"></i><?=
            h(__('Machine-derived')) ?></span>
    <?php
    $headerSub = ob_get_clean();
    ?>

    <?= $this->element('Values/View/value_panel_header', array(
        'panelTitle' => __('Near-matches'),
        'panelIcon' => 'fas fa-code-compare',
        'panelColor' => 'var(--vp-rel-near)',
        'panelSub' => $headerSub,
        'panelExtra' => $headerExtra,
    )) ?>

    <?php if (empty($near['engines'])): ?>

        <div class="p-3">
            <div class="vp-empty">
                <i class="fas fa-code-compare"></i>
                <span>
                    <?php if ($primaryType === null): ?>
                        <?= __('This value has no attribute on the'
                            . ' instance, so there is nothing for a'
                            . ' near-match engine to compare.') ?>
                    <?php else: ?>
                        <?= h(sprintf(
                            __('No near-match engine applies to %s.'),
                            $primaryType
                        )) ?>
                    <?php endif; ?>
                </span>
            </div>
        </div>

    <?php else: ?>

        <div class="vp-rel-cap">
            <i class="fas fa-triangle-exclamation"
               title="<?= h(__(
                   'A row here never means the two values are the same.'
               )) ?>"></i>
            <span>
                <?= sprintf(
                    __(
                        'A near-match is %s — every row names the engine'
                        . ' that produced it and how close the match is.'
                    ),
                    '<strong>' . h(__('not equality')) . '</strong>'
                ) ?>
            </span>
        </div>

        <?php
        /**
         * One engine's rows. Two engines produce them and they differ
         * only in what the first two columns are called, so the table
         * is written once — a second copy is a second place for the
         * `Similarity ≥` control to stop agreeing with the bar.
         *
         * @param array $engine
         * @param string $subject Heading for the matched value
         * @param string $scale Heading for the closeness column
         * @param string|null $extra Heading for the grounding column
         * @param callable|null $named When the engine's closeness is a
         *                     name rather than a number, the function
         *                     that words it. The bar and the row's
         *                     `data-vp-num` both go — see
         *                     `$offerSimilarity`.
         * @return void
         */
        $engineTable = function ($engine, $subject, $scale, $extra,
            $named = null
        )
            use ($view, $baseurl, $closeness, $shorten, $distributionBadge)
        {
            ?>
            <div class="table-responsive" data-vp-list-rows>
                <table class="table table-sm table-hover vp-table
                              align-middle mb-0">
                    <thead>
                        <tr>
                            <th><?= h($subject) ?></th>
                            <th class="vp-rel-num"><?= h($scale) ?></th>
                            <?php if ($extra !== null): ?>
                                <th><?= h($extra) ?></th>
                            <?php endif; ?>
                            <th><?= __('Where it sits') ?></th>
                            <th><?= __('Reported by') ?></th>
                            <th><?= __('Distribution') ?></th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($engine['rows'] as $row): ?>
                            <?php
                            /*
                             * Closeness is grounded twice: the bar is a
                             * defensible share and the column beside it
                             * is the fact. A /16 is "50%" only in the
                             * sense that half the bits are fixed;
                             * 65,536 addresses is what that means.
                             */
                            $share = $named === null
                                ? $closeness($row)
                                : null;
                            ?>
                            <tr class="vp-rel-stripe vp-rel-k-near"
                                <?php if ($share !== null): ?>
                                    data-vp-num="closeness:<?= h($share) ?>"
                                <?php endif; ?>>
                                <td class="font-monospace">
                                    <span class="vp-rel-cell"
                                          title="<?= h($row['block']) ?>"><?=
                                        h($shorten($row['block'])) ?></span>
                                </td>
                                <td>
                                    <?php if ($named !== null): ?>
                                        <?php
                                        /*
                                         * A class, not a percentage. §12
                                         * of `24b-relationships.md` is
                                         * explicit that a bar here would
                                         * be inventing a number: a
                                         * dropped character is not "80%
                                         * similar" to anything, and the
                                         * reader who sorts on it would be
                                         * sorting on a fiction.
                                         */
                                        ?>
                                        <span class="vp-rel-tag">
                                            <?= h($named($row)) ?>
                                        </span>
                                    <?php else: ?>
                                    <span class="vp-rel-bar"
                                          style="--vp-seg-color:
                                                 var(--vp-rel-near);">
                                        <span class="vp-weight-track">
                                            <span class="vp-weight-fill"
                                                  style="width: <?=
                                                      h($share) ?>%;"></span>
                                        </span>
                                        <span class="vp-rel-bar-read">
                                            <?= $row['addresses'] === null
                                                ? h($row['prefix'] . '%')
                                                : h('/' . $row['prefix']) ?>
                                        </span>
                                    </span>
                                    <?php endif; ?>
                                </td>
                                <?php if ($extra !== null): ?>
                                    <td class="font-monospace small
                                               text-nowrap">
                                        <?php
                                        /*
                                         * Arrives formatted, because a /8
                                         * of IPv6 is 2^120 and no integer
                                         * here holds it.
                                         */
                                        ?>
                                        <?= h($row['addresses']) ?>
                                    </td>
                                <?php endif; ?>
                                <td class="text-nowrap">
                                    <?php
                                    /*
                                     * The record holding the matched
                                     * value, and then the event under
                                     * it — the cell
                                     * `value_relation_references.ctp`
                                     * uses for the far end of a
                                     * reference, with this panel's own
                                     * choice of destination.
                                     *
                                     * **Both go to the themed event
                                     * view's tab**, because neither
                                     * record has a page of its own that
                                     * a reader of this theme wants:
                                     * `/attributes/view` redirects to
                                     * the event and loses which
                                     * attribute it was asked about, and
                                     * `/objects/view` does the same to
                                     * `/events/view` — the *unthemed*
                                     * event page, which is a worse place
                                     * to land than the tab. This theme's
                                     * view takes no `focus:`, so the
                                     * title carries the record's own id;
                                     * `value_relation_asserted.ctp`
                                     * reached the same two URLs the same
                                     * way.
                                     */
                                    ?>
                                    <?php if (!empty($row['object'])): ?>
                                        <a class="vp-rel-tag"
                                           href="<?= $baseurl
                                               ?>/events/view/<?=
                                               h($row['event'])
                                               ?>#tab-objects"
                                           title="<?= h(sprintf(
                                               __('%1$s object %2$s in'
                                                   . ' event %3$s'),
                                               $row['object_name'],
                                               $row['object'],
                                               $row['event']
                                           )) ?>">
                                            <i class="fas fa-cube"></i><?=
                                                h($row['object_name']) ?>
                                        </a>
                                    <?php elseif (!empty($row['attribute'])): ?>
                                        <a class="vp-rel-tag"
                                           href="<?= $baseurl
                                               ?>/events/view/<?=
                                               h($row['event'])
                                               ?>#tab-attributes"
                                           title="<?= h(sprintf(
                                               __('Attribute %1$s in event'
                                                   . ' %2$s'),
                                               $row['attribute'],
                                               $row['event']
                                           )) ?>">
                                            <i class="fas fa-tag"></i><?=
                                                h(__('attribute')) ?>
                                        </a>
                                    <?php endif; ?>
                                    <div class="vp-fact-line-sub">
                                        <a href="<?= $baseurl
                                            ?>/events/view/<?=
                                            h($row['event']) ?>"
                                           class="font-monospace small">
                                            #<?= h($row['event']) ?>
                                        </a>
                                    </div>
                                </td>
                                <td class="text-nowrap">
                                    <?= h($row['org']) ?>
                                </td>
                                <td><?= $distributionBadge($row) ?></td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
            <?php
        };

        /**
         * An engine that is not running, in one line.
         *
         * Two of the four states are a single fact — the engine does
         * not apply to a value of this type, or MISP has no such
         * engine — and a fact does not need a heading and a paragraph
         * to land. These keep the state column and the engine name the
         * active block above them uses, so the engines still read as
         * one comparable list, and they keep the reason, because an
         * engine that goes quiet without saying why is the thing this
         * section exists to refuse.
         *
         * *Active* keeps its block. So does *cannot run*: alone among
         * the four it reports on the instance rather than on the value,
         * and alone among them it is something a reader can act on.
         *
         * **This line is the slot a real engine's block replaces**,
         * and B10 proved the shape works by not using it: the
         * typosquat engine came in as a fourth engine above rather
         * than in the tree's place, and adding it was one
         * `$engineLine()`-shaped block plus an `$engineTable()` call.
         * That is why these are calls and not eleven lines of inline
         * markup apiece.
         *
         * @param string $state Label for the state column
         * @param string $name The engine's name
         * @param string $reason Why it is not running — **HTML**, so
         *                       that a type name can be monospaced;
         *                       callers escape their own values
         * @return void
         */
        $engineLine = function ($state, $name, $reason) {
            ?>
            <div class="vp-rel-engine vp-rel-engine-off
                        vp-rel-engine-line">
                <span class="vp-rel-engine-state">
                    <?= h($state) ?>
                </span>
                <div class="vp-min-w-0 flex-grow-1 small">
                    <span class="vp-rel-engine-name"><?= h($name) ?></span>
                    <span class="text-muted">&mdash; <?= $reason ?></span>
                </div>
            </div>
            <?php
        };
        ?>

        <?php if (isset($engines['cidr'])): ?>

            <?php $cidr = $engines['cidr']; ?>
            <?php if ($cidr['state'] !== 'active'): ?>
                <?php $engineLine(
                    __('Not applicable'),
                    __('CIDR containment'),
                    sprintf(
                        __('compares %1$s attributes; does not run on'
                            . ' %2$s.'),
                        '<span class="font-monospace">ip-src /'
                            . ' ip-dst</span>',
                        '<span class="font-monospace">'
                            . h($primaryType) . '</span>'
                    )
                ) ?>
            <?php else: ?>
            <div class="vp-rel-engine vp-rel-engine-on">
                <span class="vp-rel-engine-state">
                    <?= __('Active') ?>
                </span>
                <div class="vp-min-w-0 flex-grow-1">
                    <div class="fw-semibold small vp-rel-engine-name">
                        <?= __('CIDR containment') ?>
                    </div>
                    <div class="small text-muted mt-1">
                        <?= h(__n(
                            '%d network-block attribute contains this'
                            . ' address.',
                            '%d network-block attributes contain this'
                            . ' address.',
                            count($cidr['rows']),
                            count($cidr['rows'])
                        )) ?>
                        <?= __('Re-derived from the same CIDR list'
                            . ' the engine walks.') ?>
                    </div>
                </div>
            </div>

            <?php if (!empty($cidr['rows'])): ?>
                <?php $engineTable(
                    $cidr,
                    __('Containing block'),
                    __('Closeness'),
                    __('Addresses')
                ) ?>

                <div class="p-3 d-none" data-vp-list-empty>
                    <div class="vp-empty vp-empty-inline">
                        <i class="fas fa-filter"></i>
                        <span>
                            <?= __('No containing block is that'
                                . ' close.') ?>
                        </span>
                    </div>
                </div>
            <?php else: ?>
                <div class="px-3 pb-3">
                    <div class="vp-empty vp-empty-inline">
                        <i class="fas fa-code-compare"></i>
                        <span>
                            <?= __('No network block on this instance'
                                . ' contains this address. The engine'
                                . ' applies; it found nothing.') ?>
                        </span>
                    </div>
                </div>
            <?php endif; ?>
            <?php endif; ?>

        <?php endif; ?>

        <?php if (isset($engines['ssdeep'])): ?>

            <?php $ssdeep = $engines['ssdeep']; ?>
            <?php if ($ssdeep['state'] === 'not_applicable'): ?>
                <?php
                /*
                 * The paragraph this line replaces also taught what an
                 * ssdeep score looks like, with a sample badge — on the
                 * one screen where the engine never produces one. The
                 * active branch below says the same thing where a
                 * reader can see it happening, so the lesson is not
                 * lost, only moved off the screen that cannot use it.
                 */
                $engineLine(
                    __('Not applicable'),
                    __('ssdeep fuzzy similarity'),
                    sprintf(
                        __('compares %1$s attributes; does not run on'
                            . ' %2$s.'),
                        '<span class="font-monospace">ssdeep</span>',
                        '<span class="font-monospace">'
                            . h($primaryType) . '</span>'
                    )
                );
                ?>
            <?php else: ?>
            <div class="vp-rel-engine vp-rel-engine-<?= $ssdeep['state']
                === 'active' ? 'on' : 'off' ?>">
                <span class="vp-rel-engine-state">
                    <?php if ($ssdeep['state'] === 'active'): ?>
                        <?= __('Active') ?>
                    <?php else: ?>
                        <?= __('Cannot run') ?>
                    <?php endif; ?>
                </span>
                <div class="vp-min-w-0 flex-grow-1">
                    <div class="fw-semibold small vp-rel-engine-name">
                        <?= __('ssdeep fuzzy similarity') ?>
                    </div>
                    <div class="small text-muted mt-1">
                        <?php if ($ssdeep['state'] === 'unavailable'): ?>
                            <?php
                            /*
                             * A fourth state the brief does not have,
                             * and neither *not applicable* nor *no
                             * engine* would be true of it. MISP ships
                             * this engine and it applies to this value;
                             * the PHP extension it is written against
                             * is simply not loaded here.
                             */
                            ?>
                            <?= sprintf(
                                __(
                                    'This value %1$s an %2$s hash, so the'
                                    . ' engine applies — but %3$s is not'
                                    . ' loaded on this instance, so'
                                    . ' nothing can compare it.'
                                ),
                                '<strong>' . h(__('is')) . '</strong>',
                                '<span class="font-monospace">ssdeep</span>',
                                '<span class="font-monospace">'
                                    . 'ssdeep_fuzzy_compare()</span>'
                            ) ?>
                        <?php else: ?>
                            <?php
                            /*
                             * **What it compared, counted.** This
                             * sentence used to say *every other ssdeep
                             * attribute you can see* while the engine
                             * compared the hundred most recent —
                             * §4.2's finding, and the reason B11
                             * exists. Both halves are now read off the
                             * engine: how many distinct values it
                             * actually compared, and whether its
                             * candidate fetch hit its ceiling.
                             */
                            $compared = isset($ssdeep['compared'])
                                ? (int)$ssdeep['compared']
                                : 0;
                            /*
                             * **"all" belongs to the unsaturated case
                             * only.** It used to live in the plural
                             * form, so a fetch that had hit its ceiling
                             * said *compared against all 10 distinct
                             * values* on one line and *some were not
                             * compared at all* on the next. Caught by
                             * rendering the saturated branch on purpose
                             * — no value on the verification instance
                             * can reach it, which is exactly why it
                             * survived review.
                             */
                            /*
                             * **Pairs that cleared, not rows that fit.**
                             * A match with no occurrence the context
                             * fetch could reach still cleared the
                             * threshold, so counting rows here made the
                             * headline disagree with the line below it —
                             * *1 pair cleared* above *3 more hashes
                             * cleared it*. Found by rendering the
                             * unplaced branch on purpose; it is
                             * invisible whenever `unplaced` is zero,
                             * which is every value on this instance.
                             */
                            $matched = isset($ssdeep['matched'])
                                ? (int)$ssdeep['matched']
                                : count($ssdeep['rows']);
                            $comparedPhrase = empty($ssdeep['saturated'])
                                ? __n(
                                    'the one other distinct value',
                                    'all %d distinct values',
                                    $compared,
                                    $compared
                                )
                                : __n(
                                    '%d distinct value',
                                    '%d distinct values',
                                    $compared,
                                    $compared
                                );
                            ?>
                            <?= sprintf(
                                __(
                                    'Compared against %1$s of %2$s you'
                                    . ' can see, %3$s cleared the'
                                    . ' threshold of %4$d. The score is'
                                    . ' recomputed here — MISP keeps the'
                                    . ' threshold test, not the number.'
                                ),
                                '<strong>' . h($comparedPhrase) . '</strong>',
                                '<span class="font-monospace">ssdeep</span>',
                                '<strong>' . h(__n(
                                    '%d pair',
                                    '%d pairs',
                                    $matched,
                                    $matched
                                )) . '</strong>',
                                $near['threshold']
                            ) ?>
                            <?php if (!empty($ssdeep['unplaced'])): ?>
                                <?= h(sprintf(
                                    __n(
                                        '%d of them has no occurrence'
                                        . ' this fetch could reach, so'
                                        . ' it has no row below.',
                                        '%d of them have no occurrence'
                                        . ' this fetch could reach, so'
                                        . ' they have no row below.',
                                        $ssdeep['unplaced'],
                                        $ssdeep['unplaced']
                                    ),
                                    $ssdeep['unplaced']
                                )) ?>
                            <?php endif; ?>
                            <?php if (!empty($ssdeep['saturated'])): ?>
                                <?= h(sprintf(
                                    __('The candidate fetch stopped at'
                                        . ' %d attributes, so some of'
                                        . ' this type were not compared'
                                        . ' at all.'),
                                    $ssdeep['cap']
                                )) ?>
                            <?php endif; ?>
                        <?php endif; ?>
                    </div>
                </div>
            </div>

            <?php if ($ssdeep['state'] === 'active'
                && !empty($ssdeep['rows'])
            ): ?>
                <?php $engineTable(
                    $ssdeep,
                    __('Matched hash'),
                    __('Similarity'),
                    null
                ) ?>
            <?php endif; ?>
            <?php endif; ?>

        <?php endif; ?>

        <?php if (isset($engines['typosquat'])): ?>

            <?php $typo = $engines['typosquat']; ?>
            <?php if ($typo['state'] !== 'active'): ?>
                <?php $engineLine(
                    __('Not applicable'),
                    __('Look-alike spellings (typosquat)'),
                    sprintf(
                        __('generates spellings of a name; does not run'
                            . ' on %s.'),
                        '<span class="font-monospace">'
                            . h($primaryType) . '</span>'
                    )
                ) ?>
            <?php else: ?>
            <div class="vp-rel-engine vp-rel-engine-on">
                <span class="vp-rel-engine-state">
                    <?= __('Active') ?>
                </span>
                <div class="vp-min-w-0 flex-grow-1">
                    <div class="fw-semibold small vp-rel-engine-name">
                        <?php
                        /*
                         * Both names on purpose. *Look-alike
                         * spellings* says what the engine does to a
                         * reader who has never met the word;
                         * *typosquat* is what an analyst calls it, and
                         * what they would search this page for. The
                         * other three engines are named for their
                         * mechanism — CIDR, ssdeep — and can afford
                         * one name each because the mechanism is the
                         * word.
                         */
                        ?>
                        <?= __('Look-alike spellings (typosquat)') ?>
                    </div>
                    <div class="small text-muted mt-1">
                        <?php if (empty($typo['candidates'])): ?>
                            <?php
                            /*
                             * The engine applies and generated nothing,
                             * which is a third sentence again: not
                             * *does not run here* and not *found
                             * nothing*. A name with no dot, or one
                             * already at the length DNS allows, has no
                             * legal neighbour to generate.
                             */
                            ?>
                            <?= __('This name has no spelling to'
                                . ' generate: every variation would be'
                                . ' too long for DNS, or not a name at'
                                . ' all.') ?>
                        <?php else: ?>
                            <?= sprintf(
                                __('%1$s of this name were checked'
                                    . ' against every %2$s attribute you'
                                    . ' can see.'),
                                '<strong>' . h(__n(
                                    '%d candidate spelling',
                                    '%d candidate spellings',
                                    $typo['candidates'],
                                    $typo['candidates']
                                )) . '</strong>',
                                '<span class="font-monospace">domain</span>,'
                                    . ' <span class="font-monospace">'
                                    . 'hostname</span> '
                                    . h(__('and'))
                                    . ' <span class="font-monospace">'
                                    . 'domain|ip</span>'
                            ) ?>
                            <?php if (!empty($typo['rows'])): ?>
                                <?php
                                /*
                                 * Only where there are rows to say it
                                 * about. The count of what was found
                                 * belongs to the found state, and the
                                 * empty state below carries its own
                                 * sentence — saying *0 are already
                                 * here* and then *every row below is
                                 * derived* above an empty table names
                                 * rows that are not there.
                                 */
                                ?>
                                <?= sprintf(
                                    __('%s already on this instance.'),
                                    '<strong>' . h(__n(
                                        '%d is',
                                        '%d are',
                                        count($typo['rows']),
                                        count($typo['rows'])
                                    )) . '</strong>'
                                ) ?>
                                <?= __('Every row below is derived'
                                    . ' here: MISP correlates no two'
                                    . ' spellings of a value.') ?>
                            <?php endif; ?>
                        <?php endif; ?>
                    </div>
                    <?php if (!empty($typo['candidates'])): ?>
                        <div class="small text-muted mt-1">
                            <?php
                            /*
                             * What bounds a run, named in full. There is
                             * no numeric cap to confess here — generation
                             * is linear in the name's length, so the set
                             * is whatever these classes produce — but the
                             * classes *are* the bound, and a reader who
                             * cannot see them cannot tell a spelling the
                             * engine rejected from one it never tried.
                             */
                            $classNames = array();
                            foreach ($typo['classes'] as $class) {
                                $classNames[] = $permutationLabel($class);
                            }
                            ?>
                            <?= h(sprintf(
                                __('Generated by: %s. Nothing else was'
                                    . ' tried.'),
                                implode(', ', $classNames)
                            )) ?>
                        </div>
                    <?php endif; ?>
                    <?php if (!empty($typo['saturated'])): ?>
                        <div class="small text-muted mt-1">
                            <?= h(sprintf(
                                __('The fetch stopped at the %d most'
                                    . ' recent occurrences, so a'
                                    . ' look-alike seen only in older'
                                    . ' events is not listed.'),
                                $typo['cap']
                            )) ?>
                        </div>
                    <?php endif; ?>
                </div>
            </div>

            <?php if (!empty($typo['rows'])): ?>
                <?php $engineTable(
                    $typo,
                    __('Look-alike value'),
                    __('How it differs'),
                    null,
                    function ($row) use ($permutationLabel) {
                        return $permutationLabel($row['class']);
                    }
                ) ?>
            <?php elseif (!empty($typo['candidates'])): ?>
                <div class="px-3 pb-3">
                    <div class="vp-empty vp-empty-inline">
                        <i class="fas fa-code-compare"></i>
                        <span>
                            <?= __('Not one of those spellings is on'
                                . ' this instance. The engine applies;'
                                . ' it found nothing.') ?>
                        </span>
                    </div>
                </div>
            <?php endif; ?>
            <?php endif; ?>

        <?php endif; ?>

        <?php if (isset($engines['tld'])): ?>

            <?php
            /*
             * The absent engine, and the reason it is a line and no
             * longer a dashed stub box.
             *
             * The box was carrying two different jobs. One was the
             * fact — nothing in MISP computes a parent-domain,
             * registrable-domain or public-suffix relation: no
             * public-suffix list, no table, no code path — which is
             * what a reader needs and is one sentence long. The other
             * was an argument addressed to whoever next reads the
             * template, about why a gap in the brief is drawn instead
             * of quietly dropped. That argument belongs here, in the
             * source, and not on a page an analyst is trying to read
             * past: at ~217px it cost more of the section than the
             * engine that actually ran.
             *
             * Still deliberately unlike *not applicable* above it —
             * that engine exists and declines this type, this one does
             * not exist — which is why the state column says so in its
             * own words rather than reusing the label.
             *
             * **B10 did not replace this call**, which is what
             * `24b-relationships.md` §12 planned. §12.1 priced the
             * tree and found it is two engines wearing one name: a
             * parent-domain lookup at 10–51 ms that MISP genuinely has
             * no code path for, and a child lookup at 4,533 ms — worst
             * when it finds nothing, which is 96 domain values in 100 —
             * that only a schema change makes affordable. Generating
             * spellings does not make a parent-domain relation exist,
             * so the typosquat engine sits above this line instead of
             * on top of it, and the gap stays drawn.
             */
            $engineLine(
                __('No engine'),
                __('Domain / TLD tree'),
                h(__('nothing in MISP computes a parent-domain,'
                    . ' registrable-domain or public-suffix relation.'))
            );
            ?>

        <?php endif; ?>

    <?php endif; ?>

</div>
