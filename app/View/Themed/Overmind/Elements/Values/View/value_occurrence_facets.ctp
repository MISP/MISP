<?php
/**
 * The counted rail beside the occurrence table.
 *
 * Every filter carries its own count, so the filter set and the summary
 * of the value are the same object — which is the whole addition over
 * the Overview's preview of this table.
 *
 * A count here is what this viewer may see, never what the instance
 * holds. Where that differs from a number already on the page, the note
 * under the header says so: it is the one place where the gap between
 * the banner's total and the rail's is written as a number.
 *
 * Rendered inside `value_occurrence_table`'s row, not as its own ajax
 * panel — the counts and the rows they count come from one fetch.
 *
 * @var array $facets `occurrence_facets` for this value
 */
$groups = $facets['groups'];

/*
 * Order, heading and glyph are the same for every value, so they live
 * here; only the counts vary. A key with no
 * values is a group that renders nothing at all — a facet rail of
 * zeroes claims there are rows to narrow.
 */
$defined = array(
    array(
        'key' => 'organisation',
        'title' => __('Organisation'),
        'icon' => 'fas fa-building',
    ),
    array(
        'key' => 'type',
        'title' => __('Type'),
        'icon' => 'misp-icon misp-icon-attribute misp-simple',
    ),
    /*
     * Beside Type, because they answer the same shape of question — what
     * kind of thing is this row — and differ in a way the type alone
     * hides: one `ip-dst` standalone, one inside a `domain-ip` and one
     * inside a `network-socket` are three different findings.
     */
    array(
        'key' => 'object',
        'title' => __('Object'),
        'icon' => 'misp-icon misp-icon-object misp-simple',
    ),
    array(
        'key' => 'category',
        'title' => __('Category'),
        'icon' => 'fas fa-folder',
    ),
    array(
        'key' => 'ids',
        'title' => __('IDS flag'),
        'icon' => 'fas fa-shield-halved',
    ),
    array(
        'key' => 'distribution',
        'title' => __('Distribution'),
        'icon' => 'fas fa-globe',
    ),
    array(
        'key' => 'sharing_group',
        'title' => __('Sharing group'),
        'icon' => 'misp-icon misp-icon-sharing-group misp-simple',
    ),
    /*
     * One group over both scopes, matching the Tags column: a label on
     * the row's event covers the row, so *this occurrence is labelled
     * X* and *this occurrence arrived in a report labelled X* are one
     * question for a reader narrowing a table. A row carrying a tag on
     * both sides is counted once.
     *
     * Most of what it lists comes from the events: `8.8.8.8` carries 7
     * distinct attribute tags and 48 distinct event tags.
     */
    array(
        'key' => 'tag',
        'title' => __('Tag'),
        'icon' => 'misp-icon misp-icon-tag misp-simple',
    ),
    /*
     * Below Tag and keyed apart from it, because a cluster is not a
     * label: *what is this occurrence labelled* and *what is it
     * attributed to* are two questions, where the two scopes of one tag
     * were one question asked of two rows.
     *
     * It arrived with the Galaxies column and could not have arrived
     * before it — the rail's standing rule is that a filter on
     * something invisible is not a filter, and until that column
     * existed the pane drew no cluster at all.
     */
    array(
        'key' => 'galaxy',
        'title' => __('Galaxy cluster'),
        'icon' => 'misp-icon misp-icon-galaxy misp-simple',
    ),
);

/*
 * The label is the component wherever MISP has one: a distribution row
 * carries the real badge, a tag row the real chip. Rendering the level
 * as the word "3" — or the tag as its name in plain text — would make
 * the rail the one place on the page where these look like something
 * else.
 */
foreach ($groups['distribution'] as &$facet) {
    $facet['html'] = $this->element(
        'genericElementsBS5/Badges/distribution',
        array('distribution' => $facet['level'], 'full' => true)
    );
}
unset($facet);

/*
 * The tag group draws the real chip, so a rail row and the cell it
 * narrows to are the same object.
 */
foreach ($groups['tag'] as &$facet) {
    $facet['html'] = $this->element(
        'genericElementsBS5/Badges/tag',
        array(
            'tag' => $facet['tag'],
            'local' => !empty($facet['local']),
            'hiddenClass' => '',
            'showFavourite' => false,
        )
    );
}
unset($facet);

/*
 * A cluster row is the chip the Galaxies column draws, galaxy on the
 * rail. Each row carries its own galaxy rather than heading runs of
 * them, because the group's search box and `N more` fold hide rows.
 */
foreach ($groups['galaxy'] as &$facet) {
    $facet['html'] = $this->TagChip->cluster(array(
        'value' => $facet['cluster'],
        'galaxy' => empty($facet['galaxy']) ? '' : $facet['galaxy'],
    ));
}
unset($facet);

$hasState = !empty($groups['state']) || !empty($facets['deleted']);
?>
<div class="card shadow-sm mb-3 vp-panel"
     style="--vp-panel-color: var(--attribute);">

    <?php
    ob_start();
    ?>
        <button type="button" class="btn btn-sm btn-outline-danger"
                data-vp-facet-clear disabled>
            <?= __('Clear all') ?>
        </button>
    <?php
    $headerExtra = ob_get_clean();

    /*
     * "No filter applied" and "2 filters" are the same line in two
     * states rather than two lines, so the reader's eye does not have
     * to move when the first box is ticked.
     */
    ob_start();
    ?>
        <span data-vp-facet-summary>
            <span class="vp-facet-summary-none"><?=
                __('No filter applied') ?></span>
            <span class="vp-facet-summary-some"><span
                data-vp-facet-count-active>0</span> <?= __('filters') ?></span>
            &nbsp;&middot;&nbsp;
            <span data-vp-facet-rows><?= h($facets['visible']) ?></span>
            <?= __('rows') ?>
        </span>
    <?php
    $headerSub = ob_get_clean();
    ?>

    <?= $this->element('Values/View/value_panel_header', array(
        'panelTitle' => __('Filters'),
        'panelIcon' => 'fas fa-filter',
        'panelColor' => 'var(--attribute)',
        'panelSub' => $headerSub,
        'panelExtra' => $headerExtra,
    )) ?>

    <?php
    /*
     * There used to be a `.vp-facet-note` here spelling out the gap
     * between the banner's instance-wide chip count and this rail's
     * viewer-scoped one. §14.6 made every count on the page the
     * viewer's, so banner and rail now agree by construction and there
     * is no gap left to explain. The sentence is gone rather than
     * reworded: a note that exists only to reconcile two numbers has
     * nothing to say once they cannot differ.
     */
    ?>
    <div class="card-body py-0 px-3">

        <?php
        /*
         * **First in the rail, and one control rather than three.**
         *
         * First because a date is the cut a reader reaches for before
         * any of the vocabularies below it — *what has moved lately* is
         * asked of a value long before *which organisation reported it*
         * — and the group used to sit ninth, under eight lists that a
         * long tag or galaxy tail can push a screen apart.
         *
         * One control because the three dates are alternatives, not
         * conjuncts. `timestamp` is when somebody last touched the
         * attribute, `publish_timestamp` when its event was last
         * released, `Event.timestamp` when the event itself last moved;
         * an occurrence edited yesterday on an event published last
         * year is a different thing from the reverse, and neither is
         * answerable from the other. But a reader cutting on one of
         * them is not also cutting on the next, and three stacked
         * strips said otherwise — 96px of chart before the first facet
         * list, two of them describing a question nobody had asked.
         *
         * So the dropdown names the date and one pane draws it, and
         * **switching scope clears the bound the old one held**. Left
         * behind, that bound would go on filtering the table from a
         * pane the reader can no longer see, which is the one thing a
         * rail whose whole claim is *the filter set is the summary*
         * cannot do.
         *
         * Ranges rather than facet checkboxes because a date has no
         * vocabulary to tick.
         *
         * The inputs start empty and carry the span as `min`/`max`. A
         * control pre-filled with the whole span looks like a filter
         * already applied, and "no bound" must not render the same as
         * "the widest bound".
         */
        $scopes = array(
            array(
                'key' => 'timestamp',
                'label' => __('Attribute last modified'),
                'absent' => __('No occurrence here carries a'
                    . ' modification time.'),
                'note' => null,
            ),
            array(
                'key' => 'published',
                'label' => __('Event published'),
                'absent' => __('None of these occurrences sits on a'
                    . ' published event.'),
                /*
                 * An unpublished event has no publication date, so a cut
                 * on this drops those rows entirely. How many belongs
                 * beside the control rather than in the reader's head.
                 */
                'note' => empty($facets['published_unset'])
                    ? null
                    : sprintf(
                        __(
                            '%d occurrences sit on events that were'
                            . ' never published, and a date cut here'
                            . ' removes them.'
                        ),
                        $facets['published_unset']
                    ),
            ),
            /*
             * The event's own stamp, which is neither of the two above:
             * it moves when *any* attribute on the report changes, so it
             * answers "when was this report last worked on" where
             * `timestamp` answers "when was this occurrence last
             * touched". A row can be years old on a report edited this
             * morning.
             */
            array(
                'key' => 'event',
                'label' => __('Event last modified'),
                'absent' => __('No event behind these occurrences'
                    . ' carries a modification time.'),
                'note' => null,
            ),
        );
        /*
         * The first scope that has any dates at all, so the pane the
         * rail opens on is never the empty one while a working date sits
         * one entry down the list.
         */
        $timeScope = $scopes[0]['key'];
        foreach ($scopes as $scope) {
            if ($facets['time_spans'][$scope['key']] !== null) {
                $timeScope = $scope['key'];
                break;
            }
        }
        ?>
        <div class="vp-facetgrp">
            <div class="vp-subhead">
                <i class="fas fa-clock me-1"></i><?= __('Time') ?>
            </div>
            <?php
            /*
             * Not a `[data-vp-filter-key]`: this select picks which
             * question is being asked, and the shared list filter would
             * read its value as an answer and drop every row that does
             * not carry it as a facet token.
             */
            ?>
            <select class="form-select form-select-sm mb-2"
                    data-vp-time-scope
                    aria-label="<?= __('Filter rows on which date') ?>">
                <?php foreach ($scopes as $scope): ?>
                    <option value="<?= h($scope['key']) ?>"<?=
                        $scope['key'] === $timeScope ? ' selected' : '' ?>>
                        <?= h($scope['label']) ?>
                    </option>
                <?php endforeach; ?>
            </select>

            <?php foreach ($scopes as $scope): ?>
                <div data-vp-time-pane="<?= h($scope['key']) ?>"<?=
                    $scope['key'] === $timeScope ? '' : ' class="d-none"' ?>>
                    <?= $this->element(
                        'Values/View/value_occurrence_time_pane',
                        array(
                            'key' => $scope['key'],
                            'label' => $scope['label'],
                            'span' => $facets['time_spans'][$scope['key']],
                            'histogram' =>
                                $facets['time_buckets'][$scope['key']],
                            'absent' => $scope['absent'],
                            'note' => $scope['note'],
                        )
                    ) ?>
                </div>
            <?php endforeach; ?>
        </div>

        <?php
        /*
         * Its own group rather than a fourth scope: the dropdown's dates
         * replace one another, and a seen window is asked alongside any
         * of them. Rows carry an interval, so the cut keeps every
         * occurrence whose seen span overlaps the window.
         */
        ?>
        <div class="vp-facetgrp">
            <div class="vp-subhead"><?= __('First / last seen') ?></div>
            <?= $this->element(
                'Values/View/value_occurrence_time_pane',
                array(
                    'key' => 'seen',
                    'label' => __('Seen'),
                    'span' => $facets['seen_span'],
                    'histogram' => $facets['seen_buckets'],
                    'absent' => __('No occurrence here carries a first or last'
                        . ' seen.'),
                    'note' => empty($facets['seen_unset'])
                        || empty($facets['seen_span'])
                        ? null
                        : sprintf(
                            __n(
                                '%d occurrence carries no first/last seen,'
                                    . ' and a cut here removes it.',
                                '%d occurrences carry no first/last seen,'
                                    . ' and a cut here removes them.',
                                $facets['seen_unset']
                            ),
                            $facets['seen_unset']
                        ),
                    'countRows' => true,
                )
            ) ?>
        </div>

        <?php foreach ($defined as $group): ?>
            <?= $this->element('Values/View/value_facet_group', array(
                'key' => $group['key'],
                'title' => $group['title'],
                'icon' => $group['icon'],
                'values' => $groups[$group['key']],
            )) ?>
        <?php endforeach; ?>

        <?php if ($hasState): ?>
            <?php
            /*
             * Written out rather than driven by `value_facet_group`,
             * because this group is the one that mixes a facet with a
             * reveal: filtering *to* soft-deleted rows and including
             * them alongside the rest are different questions, and the
             * design only ever asks the second.
             */
            ?>
            <div class="vp-facetgrp">
                <div class="vp-subhead"><?= __('Row state') ?></div>

                <?php foreach ($groups['state'] as $index => $facet): ?>
                    <label class="vp-facet">
                        <input type="checkbox" class="form-check-input"
                               data-vp-facet-key="state"
                               value="<?= h($facet['value']) ?>"
                               id="vp-facet-state-<?= h($index) ?>">
                        <span class="vp-facet-label">
                            <?= h($facet['label']) ?>
                        </span>
                        <span class="vp-facet-count">
                            <?= h($facet['count']) ?>
                        </span>
                        <span class="vp-facet-bar"
                              style="--vp-facet-share: 100%"></span>
                    </label>
                <?php endforeach; ?>

                <?php if (!empty($facets['deleted'])): ?>
                    <?php
                    /*
                     * Included by default, unlike the Overview preview:
                     * that panel shows the value's current state, this
                     * tab is the whole table. The header's "showing n"
                     * counts these rows, so hiding them by default
                     * would make the header disagree with the tbody.
                     */
                    ?>
                    <div class="form-check form-switch mt-2 mb-0">
                        <input class="form-check-input" type="checkbox"
                               role="switch" data-vp-reveal="deleted"
                               id="vp-occ-reveal-deleted" checked>
                        <label class="form-check-label small text-muted"
                               for="vp-occ-reveal-deleted">
                            <?= h(sprintf(
                                __('Include %d soft-deleted'),
                                $facets['deleted']
                            )) ?>
                        </label>
                    </div>
                <?php endif; ?>
            </div>
        <?php endif; ?>

    </div>
</div>
