<?php
App::uses('ValueRelationTool', 'Tools/ValueIntelligence');
/**
 * Section five: the object joins that carry a pair of dates.
 *
 * **A strip over a table, and the table is still the answer.** The
 * insight in a resolution history is entirely in the dates —
 * `draculax.myq-see.com.` resolves to four addresses in fourteen days
 * in April 2017, then to nothing for four years, then to one Brazilian
 * host the day before the report that named it. Dormant-then-
 * reactivated is a different story from continuously-live.
 * `24-relationships.md` §25.1 is the worked case, and it is what the
 * span strip above the table draws: the gap between April 2017 and
 * March 2021 is a shape, and a shape is read in one glance and a column
 * of dates is not.
 *
 * The earlier argument here was that a canvas has nowhere to put that
 * reading, and against a canvas *instead of* the table it still holds —
 * which is why the strip carries no numbers, names no organisation and
 * is not clickable. It shows where the spans are; every fact about any
 * one of them is in the row underneath, and the two narrow together
 * through the one `[data-vp-list]` that owns them both.
 *
 * Three things this section is careful about:
 *
 *   the span is real   an object recording one date recorded a moment,
 *                      not a span, and is not here. 40,098 objects on
 *                      the verification instance carry exactly one
 *                      `datetime` and 32,892 of those are a flood
 *                      capture saying when its row was generated.
 *   the word is theirs the columns are `First seen` and `Last seen`,
 *                      and under each date sits the object's own name
 *                      for it — `time_first`, `first-seen`. The header
 *                      is generic so the table can be read; the label
 *                      is not, so the reader is never told the object
 *                      said something it did not.
 *   the bound is said  roughly a fifth of attributes sit in objects at
 *                      all, and most objects record no date. An empty
 *                      panel here is the common case and it says which
 *                      case it is.
 *
 * Lazily loaded from ValuesController::viewRelationDated.
 *
 * @var array $valueIntelligence
 * @var string $valueB64
 */
$relations = $valueIntelligence['relationships'];
$dated = $relations['dated'];
$siblings = $relations['siblings'];
$rows = $dated['rows'];

$icon = 'fas fa-clock-rotate-left';

/**
 * Where a related value is stored.
 *
 * **Not the neighbour's own Value Intelligence.** §25.2's reading still
 * wants the list of names on the address, but a value's page is about
 * to be one gesture away from any string on any page, and the record
 * that wrote the resolution is not. So the click goes to the object
 * that carries the dates the row is made of.
 *
 * `/events/view/<event>#tab-objects`, because the flat
 * views redirect to the event and lose which record they were asked
 * about, and this theme's event view takes no `focus:`. Every dated
 * relation is an attribute inside an object, so the tab never varies
 * and the row's own object and event go on the title.
 *
 * @param int $event
 * @return string
 */
$recordUrl = function ($event) use ($baseurl) {
    return $baseurl . '/events/view/' . (int)$event . '#tab-objects';
};

/**
 * A stored `datetime` as a reader wants it, with the object's own
 * relation underneath.
 *
 * The stored form is ISO 8601 to the microsecond with an offset, which
 * is right for a machine and unreadable in a table cell beside four
 * more of them.
 *
 * @param array $stamp `at`, `raw`, `relation`
 * @return string
 */
$stamp = function ($stamp) {
    ob_start();
    ?>
    <span class="vp-dated-stamp" title="<?= h($stamp['raw']) ?>">
        <?= h(date('Y-m-d H:i', $stamp['at'])) ?>
    </span>
    <?php if ($stamp['relation'] !== ''): ?>
        <span class="vp-dated-relation"><?= h($stamp['relation']) ?></span>
    <?php endif; ?>
    <?php
    return ob_get_clean();
};

/*
 * Whether the two ends of the span are the same instant. A resolution
 * observed once has `time_first` equal to `time_last`, and printing
 * the same timestamp twice reads as a rendering fault rather than as
 * the fact it is.
 */
$moment = function ($row) {
    return $row['first']['at'] === $row['last']['at'];
};

/*
 * The digits the list framework compares a range bound against —
 * `YmdHi`, which is what every other range control on this page speaks.
 */
$digits = function ($at) {
    return date('YmdHi', (int)$at);
};

/*
 * The facet groups this section offers, and the labels above them. The
 * keys are the model's; the order is the reader's — template first
 * because it is what the panel header already named.
 */
$facetGroups = array(
    array(
        'key' => 'datedobject',
        'title' => __('Template'),
        'icon' => 'fas fa-cube',
    ),
    array(
        /*
         * No honesty note, though the counts here are over a subset:
         * the group's own numbers sum to fewer rows than the table
         * holds because most templates record no origin, and the
         * caption above already says so. A callout repeating it inside
         * the rail cost three lines of height and pushed the two groups
         * beside it out of line with each other.
         */
        'key' => 'datedorigin',
        'title' => __('Origin'),
        'icon' => 'fas fa-satellite-dish',
    ),
    array(
        'key' => 'datedtype',
        'title' => __('Related value type'),
        'icon' => 'fas fa-shapes',
    ),
);

/*
 * A fourth group, where anything the history resolves to is one MISP
 * already knows to be benign. A resolution to a public resolver is a
 * real resolution and still the least interesting row here, which is
 * the reading the ranked table gives its own neighbours.
 *
 * The group carries the cut as well as the names: its first two
 * entries are *With a hit* and *No hit*, so one tick keeps the noise
 * and one drops it.
 *
 * Appended rather than declared, for the reason
 * `value_relation_cooccurrence` gives at greater length: the loop below
 * prints a group's indentation on every pass, and a value whose
 * relations no enabled list names has to render byte-identically to
 * what it did before.
 */
$datedListsHit = isset($dated['warninglists_listed'])
    ? (int)$dated['warninglists_listed']
    : 0;
if ($datedListsHit > 0) {
    $facetGroups[] = array(
        'key' => 'datedwarninglist',
        'title' => __('Warninglist'),
        'icon' => 'fas fa-list-check',
        'note' => sprintf(
            __(
                '%d of the rows below resolve to a value on a'
                . ' warninglist. They are dimmed rather than removed;'
                . ' the two entries above the list names keep or drop'
                . ' them.'
            ),
            $datedListsHit
        ),
    );
}
?>
<div class="card shadow-sm mb-3 vp-panel vp-rel-k-object"
     style="--vp-panel-color: var(--vp-rel-object);"
     id="vp-relation-dated"
     data-vp-list
     data-vp-rel-summary="dated"
     data-vp-rel-count="<?= h(number_format($dated['total'])) ?>"
     <?php if (!empty($dated['cap']['applied'])): ?>
         data-vp-rel-note="<?= h(__('of the objects read')) ?>"
     <?php endif; ?>>

    <?php
    ob_start();
    ?>
        <span class="vp-rel-tag me-1">
            <i class="<?= h($icon) ?>"></i><?= h(__('Dated relations')) ?>
        </span>
        <?php if (!empty($rows)): ?>
            <?= h(sprintf(
                __('%1$s from %2$s'),
                __n('%d dated relation', '%d dated relations',
                    $dated['total'], $dated['total']),
                __n('%d object', '%d objects', $dated['objects'],
                    $dated['objects'])
            )) ?>
            <?php if (!empty($dated['templates'])): ?>
                &nbsp;·&nbsp;<?= h(implode(', ', $dated['templates'])) ?>
            <?php endif; ?>
            &nbsp;·&nbsp;
        <?php endif; ?>
        <span class="vp-rel-prov"><i class="fas fa-gauge"></i><?=
            h(__('Machine-derived')) ?></span>
        &nbsp;·&nbsp;<?= h(__('object join')) ?>
    <?php
    $headerSub = ob_get_clean();
    ?>

    <?= $this->element('Values/View/value_panel_header', array(
        'panelTitle' => __('Dated relations'),
        'panelIcon' => $icon,
        'panelColor' => 'var(--vp-rel-object)',
        'panelSub' => $headerSub,
    )) ?>

    <div class="vp-rel-cap">
        <i class="fas fa-circle-info"
           title="<?= h(__(
               'Each date carries the object\'s own name for it,'
               . ' printed beneath. An object recording a single'
               . ' date recorded a moment rather than a span, and'
               . ' is not counted. Origin is the object\'s word for'
               . ' where the observation came from; most templates'
               . ' have none, and the organisation beneath it is'
               . ' who reported the event.'
           )) ?>"></i>
        <span>
            <?= __('A row is one object that records both a start'
                . ' and an end date.') ?>
        </span>
    </div>

    <div class="p-3">

        <?php if (empty($rows)): ?>

            <div class="vp-empty">
                <i class="<?= h($icon) ?>"></i>
                <span>
                    <?php if ($dated['in_objects'] === 0): ?>
                        <?= __('This value sits in no object, so there is no object relation to date.') ?>
                    <?php elseif ($dated['read_objects'] === 0): ?>
                        <?= h(sprintf(
                            __n(
                                'This value sits in one object, and it holds no other attribute to relate it to.',
                                'This value sits in %s, and none of them holds another attribute to relate it to.',
                                $dated['in_objects']
                            ),
                            sprintf(__('%s objects'),
                                number_format($dated['in_objects']))
                        )) ?>
                    <?php elseif (!empty($dated['cap']['applied'])): ?>
                        <?php
                        /*
                         * The capped case says both numbers. "None of
                         * the 500 objects" would be true of the read
                         * and misleading about the value, which sits in
                         * 32,922 of them.
                         */
                        ?>
                        <?= h(sprintf(
                            __('None of the %1$s objects read records both a start and an end date. This value sits in %2$s altogether, and the join reads the most recently touched.'),
                            number_format($dated['read_objects']),
                            sprintf(__('%s objects'),
                                number_format($dated['in_objects']))
                        )) ?>
                    <?php else: ?>
                        <?= h(sprintf(
                            __n(
                                'The one object this value sits in records no start and end date.',
                                'None of the %s objects this value sits in records both a start and an end date.',
                                $dated['in_objects']
                            ),
                            number_format($dated['in_objects'])
                        )) ?>
                    <?php endif; ?>
                </span>
            </div>

        <?php else: ?>

            <?php
            /*
             * **Which grouping the strip is using, said out loud.** The
             * model picks it from the row count — a page or fewer and
             * every related value gets its own lane, so the strip reads
             * the succession `8.8.8.8`'s three resolutions otherwise
             * only tell in the table; above a page they are templates,
             * because `github.com`'s 46 relations in one template would
             * be 46 lanes and a second table. §9 of
             * `24b-relationships.md`.
             *
             * The column heading carries it in both cases, which is why
             * the note below only appears for the value grouping: the
             * template grouping is what this strip has always drawn and
             * what the panel header names, so a line explaining it
             * would be three lines of height spent on the case nobody
             * asks about.
             *
             * `lanes_by` defaulted, not assumed. A cached fold written
             * before this task carries no such key, and the panel's job
             * on the five minutes after a deploy is to render what it
             * always did rather than to fatal — the reason
             * `CACHE_SHAPE` moved in the same commit is that it should
             * never come to that.
             */
            $lanesBy = isset($dated['lanes_by'])
                ? $dated['lanes_by']
                : 'template';
            $byValue = $lanesBy === 'value';
            ?>
            <?= $this->element('Values/View/value_span_strip', array(
                'stripId' => 'vp-dated-strip',
                'stripSpan' => $dated['span'],
                'stripLanes' => $dated['lanes'],
                'stripHue' => 'var(--vp-rel-object)',
                'stripNoun' => __('spans'),
                /*
                 * The table's own word for the same column, so the
                 * strip introduces no vocabulary the rows below it do
                 * not already use.
                 */
                'stripLaneHead' => $byValue
                    ? __('Related value')
                    : __('Template'),
                'stripLaneIcon' => $byValue ? '' : 'fas fa-cube',
                'stripLaneMono' => $byValue,
                'stripLabel' => $byValue
                    ? __('Each dated relation as a span, in a lane per related value, over the whole period the section covers')
                    : __('Each dated relation as a span, in a lane per object template, over the whole period the section covers'),
                'stripNote' => $byValue
                    ? sprintf(
                        __('One lane per related value, oldest first, because the table is a single page at %1$s. Above %2$d rows the lanes are object templates instead.'),
                        __n('%d row', '%d rows', count($rows),
                            count($rows)),
                        (int)$dated['page_size']
                    )
                    : '',
            )) ?>

            <?php
            /*
             * The narrowing, under the strip it narrows and above the
             * table it narrows — one control between the two things it
             * changes, rather than a rail beside them.
             *
             * **The two date bounds cross keys on purpose.** `from` is
             * bound to `last` and `to` to `first`, so a row survives
             * when its span *ends* at or after the window opens and
             * *starts* at or before the window closes. That is interval
             * overlap, expressed in the range control the framework
             * already has: binding both bounds to one key would ask
             * whether a single instant fell inside the window, which
             * for a span that straddles it answers no — the resolution
             * that ran 2013→2018 would vanish from a 2015 window it
             * covers completely.
             */
            ?>
            <div class="vp-dated-controls">

                <div class="vp-dated-window">
                    <div class="vp-subhead">
                        <i class="fas fa-arrows-left-right-to-line me-1"></i>
                        <?= h(__('Overlapping')) ?>
                    </div>
                    <div class="input-group input-group-sm">
                        <input type="date" class="form-control"
                               data-vp-range-from="last"
                               min="<?= h(date('Y-m-d',
                                   $dated['span']['from'])) ?>"
                               max="<?= h(date('Y-m-d',
                                   $dated['span']['to'])) ?>"
                               aria-label="<?= h(__('Overlapping from')) ?>">
                        <span class="input-group-text"><?= __('to') ?></span>
                        <input type="date" class="form-control"
                               data-vp-range-to="first"
                               min="<?= h(date('Y-m-d',
                                   $dated['span']['from'])) ?>"
                               max="<?= h(date('Y-m-d',
                                   $dated['span']['to'])) ?>"
                               aria-label="<?= h(__('Overlapping to')) ?>">
                    </div>
                    <div class="vp-tl-why">
                        <?= h(__('A row is kept when its span overlaps the window, not only when it starts inside it.')) ?>
                    </div>
                </div>

                <?php foreach ($facetGroups as $group): ?>
                    <?= $this->element('Values/View/value_facet_group',
                        array(
                            'key' => $group['key'],
                            'title' => $group['title'],
                            'icon' => $group['icon'],
                            'note' => isset($group['note'])
                                ? h($group['note'])
                                : null,
                            'values' => isset($dated['facets'][$group['key']])
                                ? $dated['facets'][$group['key']]
                                : array(),
                        )) ?>
                <?php endforeach; ?>

            </div>

            <div class="p-3 d-none" data-vp-list-empty>
                <div class="vp-empty vp-empty-inline">
                    <i class="fas fa-filter"></i>
                    <span>
                        <?= h(__('No dated relation survives that narrowing. The strip above dims what it removed rather than redrawing.')) ?>
                    </span>
                </div>
            </div>

            <div class="table-responsive" data-vp-list-rows>
                <table class="table table-sm table-hover vp-table
                              align-middle mb-0">
                    <?php
                    /*
                     * Oldest first, which is the order the story runs
                     * in. The cut that produced these rows was taken
                     * off the other end — the most recent survive a cap
                     * — so a table that stops is missing its beginning
                     * rather than its present, and the pager says so.
                     */
                    ?>
                    <thead>
                        <tr>
                            <th scope="col"><?= __('Related value') ?></th>
                            <th scope="col"><?= __('As') ?></th>
                            <th scope="col"><?= __('First seen') ?></th>
                            <th scope="col"><?= __('Last seen') ?></th>
                            <th scope="col"><?= __('Origin') ?></th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($rows as $row): ?>
                            <tr class="vp-rel-stripe vp-rel-k-object"
                                data-vp-span-key="<?= h($row['key']) ?>"
                                data-vp-facet="<?= h(implode(' ',
                                    $row['tokens'])) ?>"
                                data-vp-times="first:<?=
                                    h($digits($row['first']['at'])) ?> last:<?=
                                    h($digits($row['last']['at'])) ?>"
                                data-vp-text="<?= h(strtolower(
                                    $row['value'] . ' ' . $row['object']
                                    . ' ' . $row['relation'] . ' '
                                    . (string)$row['origin']
                                )) ?>">
                                <td class="font-monospace">
                                    <a class="vp-rel-cell fw-semibold<?=
                                       empty($row['warninglists'])
                                           ? ''
                                           : ' vp-rel-listed' ?>"
                                       href="<?= h($recordUrl(
                                           $row['event'])) ?>"
                                       title="<?= h(sprintf(
                                           __('%1$s, in the %2$s object'
                                               . ' %3$s of event %4$s'),
                                           $row['value'],
                                           $row['object'],
                                           $row['object_id'],
                                           $row['event']
                                       )) ?>">
                                        <?= h($row['value']) ?>
                                    </a><?= empty($row['warninglists'])
                                        ? ''
                                        : $this->element(
                                            'Values/View/'
                                            . 'value_warninglist_mark',
                                            array('lists' =>
                                                $row['warninglists'])
                                        ) ?>

                                    <div class="vp-fact-line-sub">
                                        <?= h($row['type']) ?>
                                    </div>
                                </td>
                                <td>
                                    <span class="vp-rel-tag">
                                        <i class="fas fa-cube"></i><?=
                                            h($row['object']) ?>
                                    </span>
                                    <?php if ($row['relation'] !== ''): ?>
                                        <div class="vp-fact-line-sub
                                                    font-monospace">
                                            <?= h($row['relation']) ?>
                                        </div>
                                    <?php endif; ?>
                                </td>
                                <td><?= $stamp($row['first']) ?></td>
                                <td>
                                    <?php if ($moment($row)): ?>
                                        <span class="vp-dated-span"
                                              title="<?= h(__('The object recorded one instant for both ends of the span.')) ?>">
                                            <?= h(__('same instant')) ?>
                                        </span>
                                    <?php else: ?>
                                        <?= $stamp($row['last']) ?>
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <?php
                                    /*
                                     * A dash and not a sentence. Most
                                     * templates have no `origin`
                                     * relation at all, so "the object
                                     * records no origin" is the same
                                     * true statement on every one of
                                     * forty-six rows, shouting over the
                                     * organisation underneath it. The
                                     * caption in the header says what
                                     * the column is; the title says why
                                     * a cell is empty for whoever asks.
                                     */
                                    ?>
                                    <?php if ($row['origin'] !== null
                                        && $row['origin'] !== ''
                                    ): ?>
                                        <div class="vp-rel-cell"
                                             title="<?= h($row['origin']) ?>">
                                            <?= h($row['origin']) ?>
                                        </div>
                                    <?php else: ?>
                                        <span class="vp-dated-span"
                                              title="<?= h(__('This object template records no origin for the relation.')) ?>">—</span>
                                    <?php endif; ?>
                                    <div class="vp-fact-line-sub">
                                        <?= h($row['org']) ?>
                                    </div>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>

            <div class="px-1 py-2 border-top">
                <?= $this->element('Values/View/value_pager', array(
                    'size' => $dated['page_size'],
                    'shown' => count($rows),
                    'total' => $dated['total'],
                    'noun' => array(
                        'one' => __('dated relation'),
                        'many' => __('dated relations'),
                    ),
                )) ?>
            </div>

            <?php if (!empty($dated['cap']['applied'])): ?>
                <div class="vp-fact-line-sub mt-2">
                    <i class="fas fa-scissors"></i>
                    <?= h(sprintf(
                        __('This value sits in %1$s. The join read the %2$s most recently touched, so a dated relation in an older object is not on this list.'),
                        __n('%d object', '%d objects',
                            $dated['in_objects'],
                            number_format($dated['in_objects'])),
                        number_format($dated['cap']['limit'])
                    )) ?>
                </div>
            <?php endif; ?>

        <?php endif; ?>

        <?php if (!empty($relations['suppressed'])): ?>
            <div class="vp-fact-line-sub mt-2">
                <i class="fas fa-circle-info"></i>
                <?= __('Every event this value appears in was too large to read for co-occurrence. Object joins are read per object rather than per event, so this section is unaffected by that.') ?>
            </div>
        <?php endif; ?>

        <div class="vp-fact-line-sub mt-2">
            <i class="fas fa-clock"></i>
            <?= $this->element('Values/View/value_read_age', array(
                'readAt' => isset($relations['read_at'])
                    ? $relations['read_at'] : 0,
                'prefix' => __('Folded from the object join read %s.'),
            )) ?>
        </div>

    </div>

</div>
