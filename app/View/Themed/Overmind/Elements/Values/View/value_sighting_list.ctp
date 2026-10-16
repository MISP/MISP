<?php
/**
 * The individual sightings, newest first, following the chart's brush.
 *
 * `Reported against` is the column a value-scoped list cannot do
 * without. Ten occurrences of one value can each be sighted separately,
 * and a flat list of forty-seven reports with no occurrence column
 * silently merges them into one thing that was seen forty-seven times.
 *
 * `Source` prints an em dash far more often than it prints a string,
 * which is worth showing rather than hiding: it is how a reader learns
 * that MISP's sighting source is optional and mostly unused, instead of
 * assuming this instance has lost it.
 *
 * The count in the header is the viewer's. `Plugin.Sightings_policy` can
 * hide whole sightings on events another organisation owns, so this list
 * is what you may see and not what the instance holds — said in words at
 * the foot of the panel rather than left for the reader to discover by
 * comparing two pages.
 *
 * Lazily loaded from ValuesController::viewSightingList.
 *
 * @var array $valueIntelligence
 * @var string $valueB64
 */
$rows = array_reverse($valueIntelligence['sighting_rows']);
$total = count($rows);
$pageSize = 10;

/*
 * Keyed by `Sighting::TYPE`'s own ints. The labels are spelt out rather
 * than taken from that constant, which stores `false-positive` for the
 * API's benefit and reads as a slug in a table cell.
 */
$types = array(
    0 => array(
        'label' => __('sighting'),
        'class' => 'vp-sight-badge-yes',
    ),
    1 => array(
        'label' => __('false positive'),
        'class' => 'vp-sight-badge-no',
    ),
    2 => array(
        'label' => __('expiration'),
        'class' => 'vp-sight-badge-exp',
    ),
);

/*
 * The five columns, named once so the headings and the sort tokens
 * cannot come to disagree about which columns exist or what they sort
 * on. The key is what the script compares; the label is what it says.
 */
$columns = array(
    'org' => __('Organisation'),
    'source' => __('Source'),
    'date' => __('Date'),
    'type' => __('Type'),
    'against' => __('Reported against'),
);

/**
 * One sortable token per column, built to sort lexicographically, which
 * is the contract `value_occurrence_table` already writes its rows to:
 * zero-padded numbers, `YmdHi` dates, lowercased text, so the script
 * needs one comparison and no knowledge of what any column holds.
 *
 * Cell text would not do it. `Event 9` sorts after `Event 10` compared
 * as text, and the type column reads as three unrelated words where the
 * order a reader wants is the one MISP itself gives them — a sighting,
 * then a contradiction, then an expiration.
 *
 * An empty token means the row has no value for that column, and the
 * script puts those last in both directions: a report carrying no
 * source is not alphabetically first.
 *
 * @param array $row
 * @return array `vp-sort-<column>` => token
 */
$sortKeys = function ($row) {
    return array(
        'vp-sort-org' => mb_strtolower($row['org']),
        'vp-sort-source' => mb_strtolower((string)$row['source']),
        /*
         * The digits of the printed wall clock rather than the epoch.
         * The date is rendered server-side, so ordering by epoch would
         * order the rows by a clock the reader cannot see.
         */
        'vp-sort-date' => preg_replace('/\D/', '', $row['date']),
        'vp-sort-type' => (string)$row['type'],
        // The event first, so every report filed against one occurrence
        // lands together — which is the whole reason for the column.
        'vp-sort-against' => str_pad(
            (string)(int)$row['against']['event'],
            12,
            '0',
            STR_PAD_LEFT
        ) . ' ' . mb_strtolower((string)$row['against']['type']),
    );
};

/**
 * The sort tokens as attributes, plus the row's position in the order
 * the model sent.
 *
 * Reordering moves the rows themselves, so "unsorted" has to be
 * restorable rather than merely stoppable — the third click sorts by
 * this, and without it the newest-first order would be gone after the
 * first click with no column left to get it back.
 *
 * @param array $row
 * @param int $index
 * @return string
 */
$rowSort = function ($row, $index) use ($sortKeys) {
    $data = $sortKeys($row);
    $data['vp-sort-default'] = str_pad(
        (string)$index,
        6,
        '0',
        STR_PAD_LEFT
    );
    $out = '';
    foreach ($data as $key => $token) {
        $out .= ' data-' . $key . '="' . h($token) . '"';
    }
    return $out;
};

$subtitle = $total === 0
    ? h(__('No individual sighting to list'))
    : '<span data-vp-sight-in-range>' . h($total) . '</span> '
        . h(__('in the selected range')) . ' · '
        . h(sprintf(__('%s in total'), $total));
?>
<div class="card shadow-sm mb-3 vp-panel"
     style="--vp-panel-color: var(--sighting);"
     data-vp-sight-list
     data-vp-sight-page-size="<?= (int)$pageSize ?>">

    <?= $this->element('Values/View/value_panel_header', array(
        'panelTitle' => __('Individual sightings'),
        'panelIcon' => 'misp-icon misp-icon-sighting misp-simple',
        'panelColor' => 'var(--sighting)',
        'panelSub' => $subtitle,
    )) ?>

    <?php if ($total === 0): ?>

        <div class="p-3">
            <div class="vp-empty">
                <span class="misp-icon misp-icon-sighting misp-simple"></span>
                <span><?= __('Nobody has reported seeing this.') ?></span>
            </div>
        </div>

    <?php else: ?>

        <?php
        /*
         * The same primitive the Overview's type filter uses, driven
         * here by the navigator rather than by a chip. It stays hidden
         * until the brush actually narrows something: a note that
         * always says "showing everything" trains the reader to stop
         * reading it.
         */
        ?>
        <div class="vp-filter-note d-none" data-vp-sight-range-note>
            <i class="fas fa-filter"></i>
            <span>
                <?= h(__('Range')) ?>
                <strong data-vp-sight-range-from></strong>
                →
                <strong data-vp-sight-range-to></strong>
                ·
                <strong data-vp-sight-range-shown></strong>
                <?= h(sprintf(__('of %s sightings'), $total)) ?>
            </span>
            <button type="button" class="vp-filter-clear ms-auto"
                    data-vp-sight-clear>
                <?= __('Clear') ?>
            </button>
        </div>

        <div class="table-responsive" data-vp-sight-rows>
            <table class="table table-sm align-middle vp-table mb-0">
                <?php
                /*
                 * Every column sorts, clicking the heading: ascending,
                 * descending, then back to the order the model sent.
                 * Three states and not two because that order is itself
                 * meaningful — newest report first — and no column
                 * would bring it back.
                 *
                 * A real button, so the heading is reachable and
                 * operable from the keyboard, carrying MISP's own
                 * `sortable-header`/`sort-icon` so a sortable heading
                 * here looks like one anywhere else on the instance.
                 */
                ?>
                <thead>
                    <tr>
                        <?php foreach ($columns as $key => $label): ?>
                            <th>
                                <button type="button" class="vp-th-sort"
                                        data-vp-sort-col="<?= h($key) ?>">
                                    <span class="sortable-header"><?=
                                        h($label)
                                    ?><i class="sort-icon"></i></span>
                                </button>
                            </th>
                        <?php endforeach; ?>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($rows as $index => $row): ?>
                        <?php $type = $types[$row['type']]; ?>
                        <tr data-vp-sight-date="<?=
                                h(substr($row['date'], 0, 10)) ?>"<?=
                                $rowSort($row, $index) ?>
                            class="<?= $index >= $pageSize ? 'd-none' : '' ?>">
                            <td class="fw-semibold">
                                <?php
                                /*
                                 * Null exactly when there is nowhere to
                                 * send the reader: `Sightings_anonymise`
                                 * blanks the name and zeroes the id on a
                                 * foreign report, and those all print as
                                 * one `Others`. Linking that label to
                                 * whichever organisation the row still
                                 * carried would undo the anonymisation.
                                 */
                                ?>
                                <?php if ($row['org_id'] === null): ?>
                                    <?= h($row['org']) ?>
                                <?php else: ?>
                                    <a href="<?= $baseurl
                                            ?>/organisations/view/<?=
                                            h($row['org_id']) ?>"
                                       class="vp-sight-link">
                                        <?= h($row['org']) ?>
                                    </a>
                                <?php endif; ?>
                            </td>
                            <td>
                                <?php if ($row['source'] === null): ?>
                                    <span class="text-muted">—</span>
                                <?php else: ?>
                                    <?= h($row['source']) ?>
                                <?php endif; ?>
                            </td>
                            <td class="font-monospace text-nowrap">
                                <?= h($row['date']) ?>
                            </td>
                            <td>
                                <span class="vp-sight-badge <?=
                                    h($type['class']) ?>">
                                    <?= h($type['label']) ?>
                                </span>
                            </td>
                            <td class="text-nowrap">
                                <?php
                                /*
                                 * To the event's Attributes tab and not
                                 * to the event itself: the column names
                                 * an occurrence, and that tab is the
                                 * nearest the event view gets to one —
                                 * `/attributes/view` redirects to the
                                 * event and loses which attribute it
                                 * was asked about.
                                 *
                                 * The title carries the occurrence's own
                                 * id, which is the only thing that tells
                                 * two occurrences of this value in one
                                 * event apart; the cell has room for the
                                 * event and the type and no more.
                                 */
                                $against = $row['against'];
                                $title = $against['attribute'] === null
                                    ? __('Open the event')
                                    : sprintf(
                                        __('Attribute %1$s in event %2$s'),
                                        $against['attribute'],
                                        $against['event']
                                    );
                                ?>
                                <a href="<?= $baseurl ?>/events/view/<?=
                                        h($against['event'])
                                    ?>#tab-attributes"
                                   class="vp-sight-link"
                                   title="<?= h($title) ?>">
                                    <span class="vp-sight-against">
                                        <?= h(sprintf(
                                            __('Event %s'),
                                            $against['event']
                                        )) ?>
                                    </span>
                                </a>
                                <span class="vp-sight-against-type">
                                    <?= h($against['type']) ?>
                                </span>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>

        <?php
        /*
         * Only a brush can produce this. A value with no sightings at
         * all has its own empty state above, and "no sightings in this
         * range" over it would be a different and false claim.
         */
        ?>
        <div class="p-3 d-none" data-vp-sight-empty>
            <div class="vp-empty vp-empty-inline">
                <span class="misp-icon misp-icon-sighting misp-simple"></span>
                <span>
                    <?= __('No sighting was reported in the range you'
                        . ' selected.') ?>
                </span>
            </div>
        </div>

        <div class="vp-sight-foot">
            <span>
                <?= h(__('Showing')) ?>
                <strong data-vp-sight-shown><?=
                    h(min($pageSize, $total)) ?></strong>
                <?= h(__('of')) ?>
                <strong data-vp-sight-of><?= h($total) ?></strong>
            </span>
            <button type="button" class="vp-filter-clear"
                    data-vp-sight-more
                    <?= $total <= $pageSize ? 'hidden' : '' ?>>
                <?= __('load the rest') ?>
            </button>
        </div>

        <div class="vp-acl-note vp-acl-note-band">
            <i class="fas fa-user-shield"></i>
            <span><?=
                h($valueIntelligence['sighting_notes']['policy'])
            ?></span>
        </div>

    <?php endif; ?>

</div>
