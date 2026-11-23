<?php
/**
 * One module's answer.
 *
 * The fragment `viewEnrichmentRun` returns, injected into the pane the
 * run came from. **Nothing here is written into MISP**: a finding reaches
 * an event only when the reader picks it and creates one from the page's
 * new event dialog. The answer itself is kept for the organisation
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
App::uses('ValueNewEventTool', 'Tools/ValueIntelligence');

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
    'ok' => array('fa-circle-check'),
    'silent' => array('fa-circle-minus'),
    'error' => array('fa-triangle-exclamation'),
    'timeout' => array('fa-hourglass-half'),
    'refused' => array('fa-ban'),
    'profile_refused' => array('fa-ban'),
    'unreachable' => array('fa-plug-circle-xmark'),
    'ineligible' => array('fa-circle-question'),
    'auto_not_allowed' => array('fa-hand'),
    'auto_typed' => array('fa-hand'),
    'needs_occurrence' => array('fa-ban'),
    'expired' => array('fa-clock-rotate-left'),
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

$canPick = $this->Acl->canAccess('values', 'newEvent');

/**
 * What a finding offers the new event dialog: its fingerprint, or nothing
 * when it is the value itself, which every event made here holds anyway.
 *
 * @param array $item
 * @param string $kind attribute|object|element
 * @return array|null
 */
$pickFor = function (array $item, $kind) use ($canPick, $run, $valueIntelligence) {
    if (!$canPick) {
        return null;
    }
    if (ValueNewEventTool::isValueItself($item, $kind, $valueIntelligence['value'])) {
        return array('self' => true);
    }
    return array('fp' => ValueNewEventTool::fingerprint($item, $kind, $run['module']));
};

// On the row itself, so the copies the All results pane makes still say where they came from.
$pickAttr = function ($pick) use ($run) {
    return empty($pick['fp']) ? '' : ' data-vp-ne-fp="' . h($pick['fp']) . '"'
        . ' data-vp-ne-module="' . h($run['module']) . '"'
        . ' data-vp-ne-type="' . h($run['type']) . '"';
};

$pickControl = function ($pick) {
    if ($pick === null) {
        return '';
    }
    if (!empty($pick['self'])) {
        $note = __('This is the value itself — it is always in the event.');
        return '<span class="vp-ne-self" title="' . h($note) . '">'
            . '<i class="fas fa-lock" aria-hidden="true"></i>'
            . '<span class="visually-hidden">' . h($note) . '</span></span>';
    }
    return '<button type="button" class="btn btn-sm btn-outline-primary vp-ne-pick"'
        . ' data-vp-ne-pick aria-pressed="false"'
        . ' title="' . h(__('Pick this finding for a new event')) . '">'
        . '<i class="fas fa-plus" aria-hidden="true"></i>'
        . '<span data-vp-ne-pick-label>' . h(__('Pick')) . '</span></button>';
};

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
 * Objects open until their attribute rows pass this budget, the first one
 * always; the rest stay folded rows, as in the objects index, each naming
 * the first value that tells it from its siblings. `circl_passivedns`
 * (two hundred objects of seven rows) opens the first three.
 */
$rowBudget = 24;

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

    <?php
    $labels = array(
        'ok' => __('Answered'),
        'silent' => __('Answered with nothing'),
        'error' => __('Module error'),
        'timeout' => __('Ran out of time'),
        'refused' => __('Not sent'),
        'profile_refused' => __('Never run, by your profile'),
        'unreachable' => __('Service did not answer'),
        'ineligible' => __('Not offered for this value'),
        'auto_not_allowed' => __('Not run on its own'),
        'auto_typed' => __('Not run on its own'),
        'needs_occurrence' => __('Not sent'),
        'expired' => __('No longer kept'),
    );
    $tones = array('ok' => 'ok', 'timeout' => 'warn', 'error' => 'bad', 'refused' => 'bad', 'unreachable' => 'bad');
    $answered = in_array($state, array('ok', 'silent', 'error', 'timeout'), true);
    ?>
    <div class="vp-e-res-head" title="<?= h($heading) ?>">
        <span class="vp-e-res-state is-<?= h(isset($tones[$state]) ? $tones[$state] : 'quiet') ?>">
            <i class="fas <?= h($mark[0]) ?>" aria-hidden="true"></i>
            <?= h(isset($labels[$state]) ? $labels[$state] : $heading) ?>
            <?php if ($answered): ?>
                <?php if (!empty($run['from_store'])): ?>
                    <span class="vp-e-res-age" title="<?= h(__('Kept for your organisation. Nothing was sent anywhere to show you this.')) ?>">
                        <?= $this->element('Values/View/value_enrichment_age', array('askedAge' => $run['age'])) ?>
                    </span>
                <?php else: ?>
                    <span class="vp-e-res-age"><?= h(__('just now')) ?></span>
                <?php endif; ?>
            <?php endif; ?>
        </span>
        <span class="vp-e-res-meta">
            <?php if ($run['type'] !== null): ?>
                <span><?= h(__('asked as')) ?> <span class="vp-e-type"><?= h($run['type']) ?></span></span>
            <?php endif; ?>
            <span><?= h(sprintf(__('took %d ms'), $run['took'])) ?></span>
            <?php if ($state === 'ok'): ?>
                <span><?= h(sprintf(__n('%s element', '%s elements', $run['total']), number_format($run['total']))) ?></span>
            <?php endif; ?>
            <span title="<?= h(__('The answer is kept for your organisation so that opening this value again does not ask the module again. Nothing is written into MISP until you pick it for an event.')) ?>">
                <i class="fas fa-database" aria-hidden="true"></i> <?= h(__('kept for your organisation, not added to any event')) ?>
            </span>
        </span>
        <?php if ($answered): ?>
            <span class="vp-e-res-acts">
                <?= $this->element('Values/View/value_enrichment_button', array(
                    'module' => array('name' => $run['module'], 'type' => $run['type']),
                    'canRun' => true,
                    'noRun' => '',
                    'label' => __('Ask again'),
                )) ?>
            </span>
        <?php endif; ?>
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
        <?php
        $kept = isset($run['kept']) ? (int)$run['kept'] : (int)$run['shown'];
        $more = $kept > $run['shown'];
        ?>
        <div class="vp-e-res-prose">
            <div class="vp-e-partial">
                <i class="fas fa-scissors"></i>
                <span><?= h(sprintf(
                    __('Showing %1$s of %2$s elements.'),
                    number_format($run['shown']),
                    number_format($run['total'])
                )) ?>
                <?php if ($kept < $run['total']): ?>
                    <?= h(sprintf(
                        __('MISP kept the first %1$s of the %2$s.'),
                        number_format($kept),
                        number_format($run['total'])
                    )) ?>
                <?php endif; ?></span>
                <?php if ($more): ?>
                    <button type="button" class="btn btn-link vp-e-showall"
                            data-vp-e-run="<?= h($run['module']) ?>"
                            data-vp-e-mode="stored" data-vp-e-all="1"
                            data-vp-e-type="<?= h($run['type']) ?>">
                        <i class="fas fa-chevron-down" data-vp-e-icon></i>
                        <span data-vp-e-label><?= h(sprintf(
                            $kept < $run['total']
                                ? __('Show the %s kept')
                                : __('Show all %s'),
                            number_format($kept)
                        )) ?></span>
                    </button>
                <?php endif; ?>
            </div>
        </div>
    <?php endif; ?>

    <?php if (isset($run['known_checked'])
        && $run['known_checked'] < $run['shown']
    ): ?>
        <div class="vp-e-res-prose">
            <div class="vp-e-known-note">
                <i class="fas fa-circle-info" aria-hidden="true"></i>
                <?= h(sprintf(
                    __('“Already in MISP” is checked on the first %1$s'
                        . ' of these %2$s elements only.'),
                    number_format($run['known_checked']),
                    number_format($run['shown'])
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
        ? ValueRendererTool::drawFor(
            array($run),
            $valueIntelligence['facts'] ?? array()
        )
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

    <?php
    /*
     * What the module returned, drawn as the indexes draw attributes and
     * objects: the shared value cell, category, type and IDS badges, the
     * object header. Nothing a module's answer has not got yet (distribution,
     * tags, sightings, correlations) gets a column.
     */
    $valueCell = function (array $attribute, $short = false) use ($knownChip) {
        return $this->element('genericElementsBS5/IndexTable/Fields/attribute_value', array(
            'row' => array('Attribute' => $attribute),
            'field' => array('data_path' => 'Attribute', 'remote' => true, 'show_distribution' => false),
        )) . $knownChip($attribute, $short);
    };
    $idsCell = function (array $attribute) {
        return $this->element('genericElementsBS5/IndexTable/Fields/ids', array(
            'row' => $attribute,
            'field' => array('data_path' => 'to_ids', 'readonly' => true),
        ));
    };
    $attributeHead = '<thead><tr><th>' . h(__('Value')) . '</th><th>' . h(__('Category')) . '</th>'
        . '<th>' . h(__('Type')) . '</th><th class="text-center">' . h(__('IDS')) . '</th>';
    ?>

    <?php if (!empty($run['attributes'])): ?>
        <div data-vp-e-section>
            <div class="vp-e-group">
                <span class="misp-icon misp-icon-attribute misp-hexagone" aria-hidden="true"></span>
                <span data-vp-e-group-n><?= h(sprintf(
                    __n('%d attribute', '%d attributes', count($run['attributes'])),
                    count($run['attributes'])
                )) ?></span>
            </div>
            <div class="table-responsive">
                <table class="table table-hover align-middle mb-0 ix-table vp-e-table">
                    <?= $attributeHead ?><?= $canPick ? '<th></th>' : '' ?></tr></thead>
                    <tbody>
                        <?php foreach ($run['attributes'] as $attribute): ?>
                            <?php $pick = $pickFor($attribute, 'attribute'); ?>
                            <tr data-vp-e-item<?= $pickAttr($pick) ?>>
                                <td class="text-break"><?= $valueCell($attribute) ?></td>
                                <td><?= $this->element('genericElementsBS5/Badges/category', array('category' => $attribute['category'] ?? '', 'full' => false)) ?></td>
                                <td><?= $this->element('genericElementsBS5/Badges/type', array('type' => $attribute['type'] ?? '')) ?></td>
                                <td class="text-center"><?= $idsCell($attribute) ?></td>
                                <?php if ($canPick): ?>
                                    <td class="vp-e-pickcell"><?= $pickControl($pick) ?></td>
                                <?php endif; ?>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
    <?php endif; ?>

    <?php if (!empty($run['objects'])): ?>
        <div data-vp-e-section>
            <div class="vp-e-group">
                <span class="misp-icon misp-icon-object misp-hexagone" aria-hidden="true"></span>
                <span data-vp-e-group-n><?= h(sprintf(
                    __n('%d object', '%d objects', count($run['objects'])),
                    count($run['objects'])
                )) ?></span>
                <?php if (count($run['objects']) > 1): ?>
                    <button type="button" class="vp-e-allfold"
                            data-vp-e-fold-all="open"
                            data-vp-e-open-label="<?= h(__('Expand all')) ?>"
                            data-vp-e-close-label="<?= h(__('Collapse all')) ?>">
                        <i class="fas fa-chevron-down" data-vp-e-fold-icon></i>
                        <span data-vp-e-fold-label><?= h(__('Expand all')) ?></span>
                    </button>
                <?php endif; ?>
            </div>
            <div class="table-responsive">
                <table class="table align-middle mb-0 ix-table oi-table vp-e-table">
                    <?php $left = $rowBudget; ?>
                    <?php foreach ($run['objects'] as $object): ?>
                        <?php
                        $rows = count($object['attributes']);
                        // The first object always opens; the rest while the open rows stay scannable.
                        $open = $left === $rowBudget || $left - $rows >= 0;
                        $left -= $rows;

                        // The header names the first value that tells this object from its siblings.
                        $first = null;
                        foreach ($object['attributes'] as $attribute) {
                            $value = (string)$attribute['value'];
                            $relation = (string)$attribute['relation'];
                            if ($value === '' || ($manyObjects && isset($common[$relation]) && $common[$relation] !== false)) {
                                continue;
                            }
                            if ($first === null || (mb_strlen((string)$first['value']) < 3 && mb_strlen($value) >= 3)) {
                                $first = $attribute;
                            }
                            if (mb_strlen($value) >= 3) {
                                break;
                            }
                        }
                        if ($first === null && !empty($object['attributes'])) {
                            $first = reset($object['attributes']);
                        }
                        $pick = $pickFor($object, 'object');
                        ?>
                        <tbody data-vp-e-item data-vp-obj<?= $pickAttr($pick) ?>>
                            <tr<?= $open ? ' class="oi-open"' : '' ?>>
                                <td class="oi-col-object" title="<?= h((string)($object['description'] ?? '')) ?>">
                                    <div class="oi-object">
                                        <button type="button" class="oi-expand" data-vp-obj-disc
                                                aria-expanded="<?= $open ? 'true' : 'false' ?>"
                                                title="<?= h(__('Show its attributes')) ?>">
                                            <i class="fas fa-chevron-right" aria-hidden="true"></i>
                                        </button>
                                        <?= $this->element('Objects/object_header', array(
                                            'object' => array(
                                                'name' => $object['name'],
                                                'meta-category' => $object['meta_category'] ?? '',
                                                'template_version' => $object['template_version'] ?? null,
                                            ),
                                            'ctx' => array(
                                                'count' => $rows,
                                                'deleted' => false,
                                                'distribution' => false,
                                                'firstValue' => $first === null ? '' : (string)$first['value'],
                                                'firstRelation' => $first === null ? '' : (string)$first['relation'],
                                            ),
                                        )) ?>
                                    </div>
                                    <?= $this->element('genericElementsBS5/Badges/comment', array('comment' => $object['comment'] ?? '', 'class' => 'oi-comment')) ?>
                                </td>
                                <?php if ($canPick): ?>
                                    <td class="vp-e-pickcell"><?= $pickControl($pick) ?></td>
                                <?php endif; ?>
                            </tr>
                            <tr class="oi-detail<?= $open ? '' : ' d-none' ?>" data-vp-obj-fold>
                                <td colspan="<?= $canPick ? 2 : 1 ?>">
                                    <div class="oi-card">
                                        <?php if (empty($object['attributes'])): ?>
                                            <div class="vp-e-obj-empty"><?= h(__('The module returned this object with no attributes.')) ?></div>
                                        <?php else: ?>
                                            <table class="table table-hover align-middle mb-0 ix-table vp-e-table">
                                                <?= $attributeHead ?></tr></thead>
                                                <tbody>
                                                    <?php foreach ($object['attributes'] as $attribute): ?>
                                                        <tr>
                                                            <td class="text-break"><?= $valueCell($attribute, true) ?></td>
                                                            <td>
                                                                <div class="d-flex align-items-center gap-1">
                                                                    <?= $this->element('genericElementsBS5/Badges/category', array(
                                                                        'category' => $attribute['category'] ?? '',
                                                                        'full' => (string)($attribute['relation'] ?? '') !== '',
                                                                    )) ?>
                                                                    <?= $this->element('genericElementsBS5/Badges/object_relation', array('relation' => $attribute['relation'] ?? '')) ?>
                                                                </div>
                                                            </td>
                                                            <td><?= $this->element('genericElementsBS5/Badges/type', array('type' => $attribute['type'] ?? '')) ?></td>
                                                            <td class="text-center"><?= $idsCell($attribute) ?></td>
                                                        </tr>
                                                    <?php endforeach; ?>
                                                </tbody>
                                            </table>
                                        <?php endif; ?>
                                    </div>
                                </td>
                            </tr>
                        </tbody>
                    <?php endforeach; ?>
                </table>
            </div>
        </div>
    <?php endif; ?>

    <?php if (!empty($run['elements'])): ?>
        <div data-vp-e-section>
            <div class="vp-e-group">
                <i class="fas fa-list" aria-hidden="true"></i>
                <span data-vp-e-group-n><?= h(sprintf(
                    __n('%d element', '%d elements', count($run['elements'])),
                    count($run['elements'])
                )) ?></span>
            </div>
            <div class="table-responsive">
                <table class="table table-hover align-middle mb-0 ix-table vp-e-table">
                    <thead><tr><th><?= h(__('Value')) ?></th><th><?= h(__('Type')) ?></th><?= $canPick ? '<th></th>' : '' ?></tr></thead>
                    <tbody>
                        <?php foreach ($run['elements'] as $element): ?>
                            <?php $pick = $pickFor($element, 'element'); ?>
                            <tr data-vp-e-item<?= $pickAttr($pick) ?>>
                                <td class="text-break">
                                    <span class="fw-semibold font-monospace"><?= h($element['value']) ?></span><?= $knownChip($element, true) ?>
                                </td>
                                <td>
                                    <div class="d-flex flex-wrap gap-1">
                                        <?php foreach ($element['types'] ?? array() as $type): ?>
                                            <?= $this->element('genericElementsBS5/Badges/type', array('type' => $type)) ?>
                                        <?php endforeach; ?>
                                    </div>
                                </td>
                                <?php if ($canPick): ?>
                                    <td class="vp-e-pickcell"><?= $pickControl($pick) ?></td>
                                <?php endif; ?>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
    <?php endif; ?>


</div>
