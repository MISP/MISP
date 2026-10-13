<?php
/**
 * One module's answer.
 *
 * The fragment `viewEnrichmentRun` returns, injected into the pane the
 * run came from. **Nothing here is written into MISP** — no attribute,
 * no object, no event. The answer itself is kept for the organisation
 * since phase 11, which is what lets this same fragment be served
 * without asking anybody anything.
 *
 * Eight outcomes, deliberately not interchangeable. Phase 12 named
 * four, the live path added three — *refused*, which is MISP declining
 * to ask on the instance's behalf, *ineligible*, which is this page
 * declining a module the reader was never offered, and *unreachable*,
 * which is nothing answering at all, distinct from *timeout*, where
 * the module was asked and ran out of time — and D17 adds
 * *profile_refused*, which is the reader's own declaration saying
 * never. That last one is worded as the reader's own choice rather
 * than as a restriction, because it is the only refusal here they can
 * lift themselves. The distinction that matters most is still the old
 * one: **silent is not failure.** A module that answered with nothing
 * has done its job and reported no knowledge of this value, which is a
 * finding.
 *
 * **`Already in MISP` is the one piece of §8.3's provenance that
 * survives having no store**, and the one that does the most work: it
 * is what stops an analyst adding a duplicate. `New since <date>` was
 * a delta against a previous run and is gone.
 *
 * **A returned object is drawn the way MISP draws a stored one.** An
 * enrichment answer is mostly objects — `mmdb_lookup` returns three,
 * `circl_passivedns` returns hundreds — and the analyst's question is
 * always about the attributes inside them, never about the shell. So
 * the card carries what `Objects/index.ctp` carries (the hexagon, the
 * name, the meta-category, the template's description) and opens onto
 * the same attribute table, with the relation, the value, the type,
 * the category and the IDS flag in columns rather than run together
 * on one line.
 *
 * @var array $valueIntelligence
 * @var string $valueB64
 */
App::uses('ValueRendererTool', 'Tools/ValueIntelligence');

$run = $valueIntelligence['run'];
$state = $run['state'];

/*
 * The heading is the claim. Each of these is a different thing to have
 * happened and a reader acts differently on each, so none of them is
 * softened into "no results".
 */
$headings = array(
    'ok' => __('%s answered.'),
    'silent' => __('%s answered with nothing.'),
    'error' => __('%s could not do the job.'),
    'timeout' => __('%s ran out of time.'),
    'refused' => __('MISP did not send the query.'),
    'profile_refused' => __('Your profile says never run %s.'),
    'unreachable' => __('The enrichment service did not answer.'),
    'ineligible' => __('That module was not offered for this value.'),
    /*
     * Two outcomes phase 11 adds, and neither is a failure of the
     * module. `auto_not_allowed` is the instance declining to run
     * something on its own; `expired` is the store having held an
     * answer and no longer holding it.
     */
    'auto_not_allowed' => __('%s was not run on its own.'),
    'auto_typed' => __('%s was not run on its own.'),
    'needs_occurrence' => __('MISP did not send the query.'),
    'expired' => __('%s was asked, and the answer is no longer kept.'),
);
$heading = isset($headings[$state])
    ? $headings[$state]
    : __('%s answered.');
$heading = strpos($heading, '%s') === false
    ? $heading
    : sprintf($heading, $run['module']);

/*
 * The heading's mark. Seven outcomes and four tones: answered,
 * answered with nothing, went wrong, and might work on a second press.
 * The mark repeats what the wording already says rather than standing
 * in for it — colour alone is not a claim a reader can rely on.
 */
$marks = array(
    'ok' => array('fa-circle-check', 'vp-e-mark-ok'),
    'silent' => array('fa-circle-minus', 'vp-e-mark-quiet'),
    'error' => array('fa-triangle-exclamation', 'vp-e-mark-bad'),
    'timeout' => array('fa-hourglass-half', 'vp-e-mark-warn'),
    'refused' => array('fa-ban', 'vp-e-mark-bad'),
    'profile_refused' => array('fa-ban', 'vp-e-mark-quiet'),
    'unreachable' => array('fa-plug-circle-xmark', 'vp-e-mark-bad'),
    'ineligible' => array('fa-circle-question', 'vp-e-mark-quiet'),
    'auto_not_allowed' => array('fa-hand', 'vp-e-mark-quiet'),
    'auto_typed' => array('fa-hand', 'vp-e-mark-quiet'),
    'needs_occurrence' => array('fa-ban', 'vp-e-mark-quiet'),
    'expired' => array('fa-clock-rotate-left', 'vp-e-mark-quiet'),
);
$mark = isset($marks[$state]) ? $marks[$state] : $marks['ok'];

$prose = array(
    'silent' => __(
        'The module was asked and returned no elements. That is a'
        . ' report of no knowledge about this value, not a failure —'
        . ' it is different from never having asked, and different'
        . ' again from an error.'
    ),
    'error' => __(
        'The module itself reported a problem. A missing or wrong'
        . ' setting looks like this, and so does a third-party service'
        . ' refusing the request.'
    ),
    'timeout' => __(
        'The module was asked and did not finish in time. It may'
        . ' answer on a second press — this is not the service being'
        . ' down, and the other modules are untouched.'
    ),
    'refused' => __(
        'The query was stopped before it left the instance. An'
        . ' `enrichment-before-query` workflow can decline a query,'
        . ' and nothing was sent to anybody.'
    ),
    'profile_refused' => __(
        'Nothing was sent anywhere. This is your own declaration,'
        . ' not a restriction the instance placed on you — change'
        . ' the state in your Analyst Profile to run it.'
    ),
    'unreachable' => __(
        'Nothing answered at the configured address. Nothing was sent'
        . ' to any module.'
    ),
    'ineligible' => __(
        'A run may only name a module offered for this value, under a'
        . ' type that module accepts. Nothing was sent anywhere.'
    ),
    'auto_not_allowed' => __(
        'Your profile asks for this module to run on its own, and this'
        . ' instance does not allow that. Nothing was sent anywhere,'
        . ' and pressing Run still works.'
    ),
    'auto_typed' => __(
        'Modules only run on their own for a type you hold an'
        . ' occurrence of. Nothing was sent anywhere, and pressing Run'
        . ' still works.'
    ),
    'needs_occurrence' => __(
        'This instance checks every enrichment query against an'
        . ' `enrichment-before-query` workflow, and that check needs an'
        . ' attribute. You hold no occurrence of this value, so nothing'
        . ' was sent anywhere.'
    ),
    'expired' => __(
        'The module was asked and what it said is no longer held —'
        . ' answers are not kept forever. Nothing was sent anywhere;'
        . ' running it asks again.'
    ),
);

$noDismiss = __(
    'Disabled — a dismissal has nowhere to be remembered. Nothing'
    . ' records that a module ran, so nothing can record that you'
    . ' rejected part of what it returned.'
);

/**
 * The per-element action, drawn once and reused on every row. An object
 * takes it whole; the attribute rows inside it carry none.
 *
 * @param bool $wide Whether the label is spelled out
 * @return string
 */
$actions = function ($wide = false) use ($noDismiss) {
    $out = '<span class="vp-e-el-acts">';
    $buttons = array(
        array(__('Dismiss'), 'fa-xmark', $noDismiss),
    );
    foreach ($buttons as $button) {
        $out .= '<button type="button" disabled'
            . ' class="btn btn-sm btn-outline-secondary disabled"'
            . ' title="' . h($button[2]) . '">'
            . '<i class="fas ' . h($button[1]) . '"></i>'
            . ($wide ? '<span>' . h($button[0]) . '</span>' : '')
            . '<span class="visually-hidden">' . h($button[0])
            . '</span></button>';
    }
    return $out . '</span>';
};

/**
 * `Already in MISP`, where it is.
 *
 * @param array $element
 * @param bool $short Whether the chip is a mark rather than a phrase
 * @return string
 */
$knownChip = function (array $element, $short = false) {
    if (empty($element['known'])) {
        return '';
    }
    /*
     * The claim is about the **value string**, not about the value
     * under this type — which is the claim §8.3 makes too. One probe
     * for the whole result is what keeps this to a single query, and
     * a per-type probe was measured and removes nothing: MISP really
     * does hold a `counter` with value 1.
     *
     * What the chip is not drawn on is a value MISP would not
     * correlate on — the model asks about those and only those, so a
     * row without a chip either is not in MISP or was never a
     * duplicate anybody could make.
     */
    $title = __(
        'MISP already holds this value somewhere you can see it.'
        . ' Check before adding it again.'
    );
    if ($short) {
        /*
         * Inside an object's table the chip shares its cell with the
         * value, and the phrase there pushes the value into wrapping
         * on every row that has one. The mark keeps the column, and
         * the accessible name carries the whole claim.
         */
        return '<span class="vp-e-known vp-e-known-mark"'
            . ' title="' . h($title) . '">'
            . h(__('in MISP'))
            . '<span class="visually-hidden">'
            . ' — ' . h(__('already')) . '</span></span>';
    }
    return '<span class="vp-e-known" title="' . h($title) . '">'
        . h(__('Already in MISP')) . '</span>';
};

/*
 * A fresh CSRF token travels with the answer. They are use-once and a
 * reader runs several modules, so the fragment that arrives carries
 * the one the next run will spend — `Security::startup()` mints it on
 * this very request, after validating the one that got here.
 */
$token = isset($this->request->params['_Token']['key'])
    ? $this->request->params['_Token']['key']
    : '';

/*
 * §10's per-object expansion, decided on the attribute rows rather
 * than on the object count. The attributes are the answer — they are
 * the reason the module was asked — so the pane opens objects until
 * the open rows stop being a list a reader can scan, and folds the
 * rest. `mmdb_lookup` returns three objects of ten rows and opens
 * whole; `circl_passivedns` returns two hundred of seven and opens
 * the first eight, which is where the reader is looking.
 *
 * A folded card is not silent about what it holds: its head carries
 * the first of its values, so no object here is a shell somebody has
 * to open to find out whether it is worth opening.
 */
$rowBudget = 60;

/*
 * The filter, offered only where scanning has become the problem it
 * solves. Under a dozen elements a reader reads the list; over it
 * they are hunting for one string, and on a capped 200-element answer
 * that hunt is the whole interaction. It filters what is already on
 * the page and asks nobody anything.
 */
$filterFrom = 12;
$showFilter = $run['shown'] >= $filterFrom;

/*
 * Which relations tell one folded card from another.
 *
 * A value that is the same on all 199 passive-DNS records — every one
 * of them says `origin: https://www.circl.lu/pdns/` — cannot be what
 * a reader picks a card by, and three such values are a head that
 * says nothing 199 times. So a relation with one value across the
 * whole answer is not offered to the peek.
 */
$common = array();
foreach ($run['objects'] as $object) {
    foreach ($object['attributes'] as $attribute) {
        $relation = (string)$attribute['relation'];
        $value = (string)$attribute['value'];
        if (!array_key_exists($relation, $common)) {
            $common[$relation] = $value;
        } elseif ($common[$relation] !== $value) {
            $common[$relation] = false;
        }
    }
}
$manyObjects = count($run['objects']) > 1;
?>
<div class="vp-e-res"
     data-vp-e-result="<?= h($run['module']) ?>"
     data-vp-e-state-is="<?= h($state) ?>"
     data-vp-e-shown="<?= h($run['shown']) ?>"
     data-vp-e-total="<?= h($run['total']) ?>"
     data-vp-e-token="<?= h($token) ?>">

    <div class="vp-e-res-head">
        <i class="fas <?= h($mark[0]) ?> vp-e-mark <?= h($mark[1]) ?>"
           aria-hidden="true"></i>
        <div class="vp-e-res-headtext">
            <div class="vp-e-cold-title"><?= h($heading) ?></div>

            <?php
            /*
             * The provenance line: what the module *is* and what this
             * press cost. Chips rather than a run of text: they
             * are five unrelated facts and a reader looks for one of
             * them at a time.
             */
            ?>
            <div class="vp-e-chips">
                <?php
                /*
                 * Where the answer came from, and it leads the chips
                 * because it changes what every other one means: a
                 * `took` of 4.9 s describes a query somebody else made
                 * two hours ago, not this reader's press.
                 *
                 * When, never who (D27) — the store knows which
                 * analyst ran it and no surface says so.
                 */
                ?>
                <?php if (!empty($run['from_store'])): ?>
                    <span class="vp-e-chip"
                          title="<?= h(__(
                            'Kept for your organisation. Nothing was'
                            . ' sent anywhere to show you this.'
                          )) ?>">
                        <i class="fas fa-clock-rotate-left"
                           aria-hidden="true"></i>
                        <?= h(__('asked')) ?>
                        <?= $this->element(
                            'Values/View/value_enrichment_age',
                            array('askedAge' => $run['age'])
                        ) ?>
                    </span>
                <?php endif; ?>
                <?php if (!empty($run['kinds'])): ?>
                    <span class="vp-e-chip"><?= h(implode(
                        '+',
                        $run['kinds']
                    )) ?></span>
                <?php endif; ?>
                <?php if ($run['format'] !== null): ?>
                    <span class="vp-e-chip font-monospace"><?= h(
                        $run['format']
                    ) ?></span>
                <?php endif; ?>
                <?php if ($run['type'] !== null): ?>
                    <span class="vp-e-chip">
                        <?= h(__('asked as')) ?>
                        <span class="font-monospace"><?= h(
                            $run['type']
                        ) ?></span>
                    </span>
                <?php endif; ?>
                <span class="vp-e-chip">
                    <i class="fas fa-stopwatch"></i>
                    <?= h(sprintf(__('%d ms'), $run['took'])) ?>
                </span>
                <?php if ($state === 'ok'): ?>
                    <span class="vp-e-chip vp-e-chip-n">
                        <span class="vp-e-num"><?= h(
                            $run['total']
                        ) ?></span>
                        <?= h(__n(
                            'element returned',
                            'elements returned',
                            $run['total']
                        )) ?>
                    </span>
                <?php endif; ?>
                <?php
                /*
                 * **This said *nothing stored* until 2026-09-21**, two
                 * chips along from one reading *asked 2 hours ago* —
                 * the answer had been served out of the store it
                 * claimed did not exist. What it was reaching for is
                 * still true and is what an analyst needs: nothing
                 * here is written into MISP. Every run is kept for the
                 * organisation, and neither fact implies the other.
                 */
                ?>
                <span class="vp-e-chip vp-e-chip-quiet"
                      title="<?= h(__(
                        'The answer is kept for your organisation so'
                        . ' that opening this value again does not ask'
                        . ' the module again. Nothing is written into'
                        . ' MISP.'
                      )) ?>">
                    <i class="fas fa-database"></i>
                    <?= h(__('kept, not written')) ?>
                </span>
            </div>
        </div>

    </div>

    <?php if (isset($prose[$state])): ?>
        <div class="vp-e-res-prose">
            <div class="vp-e-cold-prose mb-0">
                <?= h($prose[$state]) ?>
            </div>
        </div>
    <?php endif; ?>

    <?php if (!empty($run['message'])): ?>
        <div class="vp-e-res-prose">
            <div class="vp-e-why">
                <div class="font-monospace small"><?= h(
                    $run['message']
                ) ?></div>
            </div>
        </div>
    <?php endif; ?>

    <?php if ($run['capped']): ?>
        <?php
        /*
         * §14.6 keeps cap notices, and this one is stated against the
         * total rather than instead of it: a reader who cannot see
         * 1,174 of 1,374 rows must not be left thinking there were
         * 200. The pressure here comes from outside MISP — the module
         * decides how much to say — which makes the total the only
         * honest thing on the line.
         */
        ?>
        <div class="vp-e-res-prose">
            <div class="vp-e-partial">
                <i class="fas fa-scissors"></i>
                <?= h(sprintf(
                    __(
                        'Showing %1$s of %2$s elements. The rest are'
                        . ' not hidden from you — they are more than'
                        . ' this panel renders.'
                    ),
                    $run['shown'],
                    $run['total']
                )) ?>
            </div>
        </div>
    <?php endif; ?>

    <?php
    /*
     * The shape's full rendering, **above** the returned data and
     * never instead of it.
     *
     * A visualisation that hid the rows it was drawn from would be one
     * an analyst cannot check, and checking it is the whole reason the
     * table below kept its cap, its stated total and its *already in
     * MISP* marks. What this adds is the reading: a hundred
     * `passive-dns` objects are a history, and a table of them is a
     * hundred rows.
     *
     * Drawn from this module's answer alone, unlike the Overview's
     * strip, which merges every module that answered the same
     * question. The pane is a module's own pane and a widget here
     * carrying somebody else's data would be answering a question the
     * rail did not ask.
     */
    $drawn = $state === 'ok'
        ? ValueRendererTool::drawFor(array($run))
        : array();
    ?>
    <?php foreach ($drawn as $shape): ?>
        <?= $this->element('Values/View/value_enrichment_shape', array(
            'shape' => $shape,
        )) ?>
    <?php endforeach; ?>

    <?php if ($showFilter): ?>
        <?php
        /*
         * Client-side over the rows already here. It never asks
         * anybody anything, which is the tab's standing promise, and
         * it says how much it is hiding rather than leaving a reader
         * to wonder whether a module returned three rows or three
         * hundred.
         */
        ?>
        <div class="vp-e-filter">
            <i class="fas fa-filter"></i>
            <input type="search" class="form-control form-control-sm"
                   data-vp-e-filter
                   placeholder="<?= h(__(
                       'Filter these results — value, type, relation'
                   )) ?>"
                   aria-label="<?= h(__('Filter these results')) ?>">
            <span class="vp-e-filter-n" data-vp-e-filter-n
                  data-vp-e-filter-fmt="<?= h(__(
                      '%1$s of %2$s shown'
                  )) ?>"></span>
        </div>
    <?php endif; ?>

    <?php if (!empty($run['attributes'])): ?>
        <div data-vp-e-section>
        <div class="vp-e-group">
            <span class="misp-icon misp-icon-attribute misp-hexagone"
                  aria-hidden="true"></span>
            <span data-vp-e-group-n><?= h(sprintf(
                __n(
                    '%d attribute',
                    '%d attributes',
                    count($run['attributes'])
                ),
                count($run['attributes'])
            )) ?></span>
        </div>
        <div class="vp-e-list">
            <?php foreach ($run['attributes'] as $attribute): ?>
                <?php
                /*
                 * Two lines, not one wrapped one. The value is what a
                 * reader is here for and it goes first at full width;
                 * the type, the category and the IDS flag are what
                 * they check afterwards, and they sit under it in a
                 * fixed order so the eye finds the same fact in the
                 * same place on every row.
                 */
                ?>
                <div class="vp-e-el" data-vp-e-item>
                    <div class="vp-e-el-body">
                        <div class="vp-e-el-top">
                            <span class="vp-e-val"><?= h(
                                $attribute['value']
                            ) ?></span>
                            <?= $knownChip($attribute) ?>
                        </div>
                        <div class="vp-e-el-sub">
                            <?php if (!empty($attribute['type'])): ?>
                                <span class="vp-e-type"><?= h(
                                    $attribute['type']
                                ) ?></span>
                            <?php endif; ?>
                            <?php if (!empty($attribute['category'])): ?>
                                <span class="vp-e-meta"><?= h(
                                    $attribute['category']
                                ) ?></span>
                            <?php endif; ?>
                            <?php if (!empty($attribute['to_ids'])): ?>
                                <span class="vp-e-ids" title="<?= h(__(
                                    'The module marked this one'
                                    . ' actionable for detection.'
                                )) ?>"><?= h(__('IDS')) ?></span>
                            <?php endif; ?>
                            <?php if (!empty($attribute['comment'])): ?>
                                <span class="vp-e-meta vp-e-el-note">
                                    <i class="fas fa-comment"></i>
                                    <?= h($attribute['comment']) ?>
                                </span>
                            <?php endif; ?>
                        </div>
                    </div>
                    <?= $actions() ?>
                </div>
            <?php endforeach; ?>
        </div>
        </div>
    <?php endif; ?>

    <?php if (!empty($run['objects'])): ?>
        <div data-vp-e-section>
        <div class="vp-e-group">
            <span class="misp-icon misp-icon-object misp-hexagone"
                  aria-hidden="true"></span>
            <span data-vp-e-group-n><?= h(sprintf(
                __n('%d object', '%d objects', count($run['objects'])),
                count($run['objects'])
            )) ?></span>
            <?php if (count($run['objects']) > 1): ?>
                <?php
                /*
                 * One press for the whole answer, in both directions.
                 * A reader comparing two hundred passive-DNS records
                 * wants every table at once; a reader who has found
                 * theirs wants the rest out of the way.
                 */
                ?>
                <button type="button" class="vp-e-allfold"
                        data-vp-e-fold-all="open"
                        data-vp-e-open-label="<?= h(__('Expand all')) ?>"
                        data-vp-e-close-label="<?= h(__('Collapse all')) ?>">
                    <i class="fas fa-chevron-down" data-vp-e-fold-icon></i>
                    <span data-vp-e-fold-label><?= h(
                        __('Expand all')
                    ) ?></span>
                </button>
            <?php endif; ?>
        </div>
        <?php $left = $rowBudget; ?>
        <?php foreach ($run['objects'] as $object): ?>
            <?php
            $rows = count($object['attributes']);
            /*
             * The first object always opens whatever it holds: a
             * hundred-row object folded on arrival would leave a pane
             * whose only content is a shut card.
             */
            $open = $left === $rowBudget || $left - $rows >= 0;
            $left -= $rows;

            /*
             * What a folded head says it holds. Values, because they
             * are what the reader is scanning for — the relations
             * repeat across every object of the same template and
             * would say the same thing on all two hundred cards.
             */
            /*
             * A column nothing in this object fills is a question the
             * object has no answer to. `mmdb_lookup` sets no IDS flag
             * on any of its ten rows, and a header over ten blanks
             * reads as ten negatives rather than as silence.
             */
            $hasCategory = false;
            $hasIds = false;
            foreach ($object['attributes'] as $attribute) {
                if (!empty($attribute['category'])) {
                    $hasCategory = true;
                }
                if (!empty($attribute['to_ids'])) {
                    $hasIds = true;
                }
            }

            $peek = array();
            $spare = array();
            foreach ($object['attributes'] as $attribute) {
                $value = (string)$attribute['value'];
                if ($value === '') {
                    continue;
                }
                $relation = (string)$attribute['relation'];
                if ($manyObjects
                    && isset($common[$relation])
                    && $common[$relation] !== false
                ) {
                    continue;
                }
                /*
                 * `count: 1` and `rrtype: A` vary across the answer
                 * and still say nothing you could find a record by.
                 * They are kept back rather than dropped: an object
                 * whose values are all this short would otherwise
                 * fold into a head with nothing on it.
                 */
                if (mb_strlen($value) < 3) {
                    $spare[] = $value;
                    continue;
                }
                $peek[] = $value;
                if (count($peek) === 3) {
                    break;
                }
            }
            while (count($peek) < 3 && !empty($spare)) {
                $peek[] = array_shift($spare);
            }
            ?>
            <div class="vp-e-obj" data-vp-e-item data-vp-e-obj>

                <?php
                /*
                 * The whole head is the control, which is what MISP's
                 * own object accordion does. A 1.15rem chevron beside
                 * a card the reader is already pointing at is a hit
                 * target they have to aim for, and there is nothing
                 * else in the head to click.
                 */
                ?>
                <button type="button"
                        class="vp-e-obj-head"
                        data-vp-e-disc
                        aria-expanded="<?= $open ? 'true' : 'false' ?>">
                    <i class="fas fa-chevron-right vp-e-obj-chev"
                       aria-hidden="true"></i>

                    <span class="misp-icon misp-icon-object misp-hexagone
                                 vp-e-obj-icon" aria-hidden="true"></span>

                    <span class="vp-e-obj-name"><?= h(
                        $object['name']
                    ) ?></span>

                    <?php if (!empty($object['meta_category'])): ?>
                        <span class="vp-e-obj-cat"><?= h(
                            $object['meta_category']
                        ) ?></span>
                    <?php endif; ?>

                    <?php if (!empty($object['comment'])): ?>
                        <span class="vp-e-obj-note"
                              title="<?= h($object['comment']) ?>">
                            <i class="fas fa-comment"></i>
                            <?= h($object['comment']) ?>
                        </span>
                    <?php endif; ?>

                    <?php if (!empty($peek)): ?>
                        <span class="vp-e-obj-peek"><?= h(implode(
                            ' · ',
                            $peek
                        )) ?><?= count($object['attributes'])
                            > count($peek) ? h(' …') : '' ?></span>
                    <?php endif; ?>

                    <span class="vp-e-obj-count"><?= h(sprintf(
                        __n(
                            '%d attribute',
                            '%d attributes',
                            $rows
                        ),
                        $rows
                    )) ?></span>
                </button>

                <div class="<?= $open ? '' : 'd-none' ?>"
                     data-vp-e-fold>

                    <?php if (!empty($object['description'])): ?>
                        <div class="vp-e-obj-desc"><?= h(
                            $object['description']
                        ) ?></div>
                    <?php endif; ?>

                    <?php if (empty($object['attributes'])): ?>
                        <div class="vp-e-obj-desc"><?= h(__(
                            'The module returned this object with no'
                            . ' attributes.'
                        )) ?></div>
                    <?php else: ?>
                        <div class="vp-e-otable-wrap">
                            <table class="vp-e-otable">
                                <thead>
                                    <tr>
                                        <th><?= h(__('Relation')) ?></th>
                                        <th><?= h(__('Value')) ?></th>
                                        <th><?= h(__('Type')) ?></th>
                                        <?php if ($hasCategory): ?>
                                            <th><?= h(
                                                __('Category')
                                            ) ?></th>
                                        <?php endif; ?>
                                        <?php if ($hasIds): ?>
                                            <th class="text-center"><?= h(
                                                __('IDS')
                                            ) ?></th>
                                        <?php endif; ?>
                                    </tr>
                                </thead>
                                <tbody>
                                <?php foreach (
                                    $object['attributes'] as $attribute
                                ): ?>
                                    <tr>
                                        <td class="vp-e-rel-name"><?= h(
                                            $attribute['relation']
                                        ) ?></td>
                                        <td>
                                            <span class="vp-e-val"><?= h(
                                                $attribute['value']
                                            ) ?></span>
                                            <?= $knownChip(
                                                $attribute,
                                                true
                                            ) ?>
                                            <?php if (!empty(
                                                $attribute['comment']
                                            )): ?>
                                                <div class="vp-e-meta
                                                            vp-e-el-note">
                                                    <?= h(
                                                        $attribute['comment']
                                                    ) ?>
                                                </div>
                                            <?php endif; ?>
                                        </td>
                                        <td>
                                            <?php if (!empty(
                                                $attribute['type']
                                            )): ?>
                                                <span class="vp-e-type"><?=
                                                    h($attribute['type'])
                                                ?></span>
                                            <?php endif; ?>
                                        </td>
                                        <?php if ($hasCategory): ?>
                                            <td class="vp-e-meta"><?= h(
                                                $attribute['category']
                                            ) ?></td>
                                        <?php endif; ?>
                                        <?php if ($hasIds): ?>
                                            <td class="text-center">
                                                <?php if (!empty(
                                                    $attribute['to_ids']
                                                )): ?>
                                                    <span class="vp-e-ids"
                                                          title="<?= h(__(
                                                            'The module'
                                                            . ' marked this'
                                                            . ' one actionable'
                                                            . ' for detection.'
                                                          )) ?>"><?= h(
                                                        __('IDS')
                                                    ) ?></span>
                                                <?php endif; ?>
                                            </td>
                                        <?php endif; ?>
                                    </tr>
                                <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                    <?php endif; ?>

                    <div class="vp-e-obj-foot">
                        <span class="vp-e-obj-footnote"><?= h(__(
                            'MISP adds an object whole.'
                        )) ?></span>
                        <?= $actions(true) ?>
                    </div>
                </div>
            </div>
        <?php endforeach; ?>
        </div>
    <?php endif; ?>

    <?php if (!empty($run['elements'])): ?>
        <div data-vp-e-section>
        <div class="vp-e-group">
            <i class="fas fa-list" aria-hidden="true"></i>
            <span data-vp-e-group-n><?= h(sprintf(
                __n(
                    '%d element',
                    '%d elements',
                    count($run['elements'])
                ),
                count($run['elements'])
            )) ?></span>
        </div>
        <div class="vp-e-list">
            <?php foreach ($run['elements'] as $element): ?>
                <div class="vp-e-el" data-vp-e-item>
                    <div class="vp-e-el-body">
                        <div class="vp-e-el-top">
                            <span class="vp-e-val"><?= h(
                                $element['value']
                            ) ?></span>
                            <?= $knownChip($element) ?>
                        </div>
                        <?php if (!empty($element['types'])): ?>
                            <div class="vp-e-el-sub">
                                <?php foreach (
                                    $element['types'] as $type
                                ): ?>
                                    <span class="vp-e-type"><?= h(
                                        $type
                                    ) ?></span>
                                <?php endforeach; ?>
                            </div>
                        <?php endif; ?>
                    </div>
                    <?= $actions() ?>
                </div>
            <?php endforeach; ?>
        </div>
        </div>
    <?php endif; ?>

    <?php
    /*
     * Offered only where a run actually happened. `ineligible` and
     * `unreachable` did not ask anything, and a *Run again* under
     * either would be inviting a press that is not the one that would
     * help. A timeout gets one, because pressing again is exactly what
     * might work. Reaching this element at all means `perm_add`, since
     * the ACL gates the action — so the control is never the disabled
     * variant here.
     */
    ?>
    <?php if (in_array(
        $state,
        array('ok', 'silent', 'error', 'timeout'),
        true
    )): ?>
        <div class="vp-e-res-foot">
            <?= $this->element(
                'Values/View/value_enrichment_button',
                array(
                    'module' => array(
                        'name' => $run['module'],
                        'type' => $run['type'],
                    ),
                    'canRun' => true,
                    'noRun' => '',
                    'label' => __('Run again'),
                )
            ) ?>
            <span class="small text-muted">
                <?= h(__(
                    'Re-running asks the module again — this page'
                    . ' remembers no previous answer to compare'
                    . ' against.'
                )) ?>
            </span>
        </div>
    <?php endif; ?>

</div>
