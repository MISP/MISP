<?php
/**
 * The newest few attribute rows carrying this value — a sample of the
 * Occurrences tab, sitting on the tab a reader lands on.
 *
 * An `index_table` over `$valueIntelligence['occurrences']`, which is shaped
 * like a `fetchAttributes` result, so the field renderers below are the
 * same ones every other MISP index uses — the event reference excepted,
 * and that one says why in its own file. No `sort` keys and no
 * `paginatorOptions`: this is the Overview summary, and the full,
 * filterable, paginated table is the Occurrences tab.
 *
 * **Eight rows since phase 31**, in one line each, with no selection
 * column and no mass-action toolbar. It drew twenty-five rows at the
 * event badge's height until then, which measured 792px against an
 * Overview whose whole left column was 1531px: a summary that had to be
 * scrolled past, in a card that scrolled internally to hold it. What
 * those rows were being read for — *who reports this, and when* — is
 * answered in one strip by `value_reporting` beneath, and the rest is
 * one *View the full table* away, a link in the card's subtitle.
 *
 * Lazily loaded into `.ajax-tab-content` from
 * ValuesController::viewOccurrences.
 *
 * @var array $valueIntelligence
 * @var string $valueB64
 */
$profile = $valueIntelligence;
$rows = $profile['occurrences'];
$stats = $profile['occurrence_stats'];
/*
 * Which taxonomies this reader asked to see first. The Tags column
 * draws one chip, so the plan decides what that chip is.
 */
$labelPlan = $profile['label_plan'];

/*
 * Two things the page filters rows by, both stated on the <tr> because
 * `row_class_callable` is the only per-row hook `index_table` offers.
 *
 * Soft-deleted occurrences are part of the value's history but not of
 * its current state, so they start hidden until asked for. The type is
 * carried as a slug: a MISP type can hold characters a class name
 * cannot — `domain|ip`. The banner's type chips are keyed by the same
 * slug, and the two forms have to agree for a chip to select anything.
 */
$typeSlug = function ($type) {
    return preg_replace('/[^a-z0-9]+/', '-', strtolower($type));
};

$rowClass = function ($row) use ($typeSlug) {
    $classes = array('vp-occ-type-' . $typeSlug($row['Attribute']['type']));
    if (!empty($row['Attribute']['deleted'])) {
        $classes[] = 'vp-occ-deleted';
        $classes[] = 'd-none';
    }
    return implode(' ', $classes);
};

// The columns the Occurrences tab draws too.
$fields = $this->ValueOccurrence->fields(array('plan' => $labelPlan));

// What the card shows; the total and the way to the rest only when it is cut short.
$truncated = $stats['shown'] < $stats['total'];
$subtitle = null;
if (!empty($rows)) {
    $subtitle = h($truncated
        ? sprintf(__n('Showing the latest occurrence', 'Showing the latest %s occurrences',
            $stats['shown']), number_format($stats['shown']))
        : sprintf(__n('Showing the only occurrence', 'Showing all %s occurrences',
            $stats['shown']), number_format($stats['shown'])));
    if ($truncated) {
        $subtitle .= ' &nbsp;·&nbsp; ' . h(sprintf(__('%s in total'), number_format($stats['total'])))
            . ' &nbsp;·&nbsp; <a href="#tab-occurrences" class="vp-head-link"'
            . ' title="' . h(__('The full, filterable occurrence table')) . '">'
            . h(__('View the full table')) . ' <i class="fas fa-arrow-right"'
            . ' aria-hidden="true"></i></a>';
    }
}

ob_start();
?>
    <?php if (!empty($stats['deleted'])): ?>
        <div class="form-check form-switch mb-0">
            <input class="form-check-input" type="checkbox" role="switch"
                   id="vp-occ-deleted-toggle">
            <label class="form-check-label small text-muted"
                   for="vp-occ-deleted-toggle">
                <?= h(sprintf(
                    __('Include %s soft-deleted'),
                    $stats['deleted']
                )) ?>
            </label>
        </div>
    <?php endif; ?>
<?php
$headerExtra = ob_get_clean();
?>
<div class="card shadow-sm mb-3 vp-panel" data-vp-occurrences
     style="--vp-panel-color: var(--attribute);">

    <?= $this->element('Values/View/value_panel_header', array(
        'panelTitle' => __('Occurrences'),
        'panelIcon' => 'misp-icon misp-icon-attribute misp-simple',
        'panelColor' => 'var(--attribute)',
        'panelSub' => $subtitle,
        'panelExtra' => trim($headerExtra) === '' ? null : $headerExtra,
    )) ?>

    <?php if (empty($rows)): ?>
        <?php
        /*
         * "No event you can see" rather than "no occurrences": for a
         * value-centric page the distinction between absent and hidden
         * is the whole point, and only one of them is knowable here.
         */
        ?>
        <div class="vp-empty">
            <span class="misp-icon misp-icon-attribute misp-simple"></span>
            <span><?= __('No event you can see carries this value.') ?></span>
        </div>
    <?php else: ?>
        <?php
        /*
         * What a type chip in the banner did, said in the panel it acted
         * on: a narrowed table with no note reads as a value with fewer
         * occurrences than the header claims.
         *
         * **The denominator is *these* rows**, and at a cap of 8 that
         * has to be said rather than implied. It was already only the
         * rows the filter chose from — rows hidden by ACL or by the
         * soft-deleted toggle were never candidates — but at 25 rows it
         * was usually also the whole value, and the wording could get
         * away with `%s of %s rows`. It cannot now: `8.8.8.8` carries
         * five `ip-src` occurrences and none of them is among its eight
         * newest, so the chip narrowing this card to zero is the
         * ordinary case and not the edge one.
         */
        ?>
        <div class="vp-filter-note d-none" data-vp-filter-note>
            <i class="fas fa-filter"></i>
            <span><?= sprintf(
                __('Type %1$s only &nbsp;·&nbsp; %2$s of the %3$s rows'
                    . ' shown here'),
                '<span class="font-monospace fw-semibold"'
                    . ' data-vp-filter-type></span>',
                '<span data-vp-filter-shown></span>',
                '<span data-vp-filter-total></span>'
            ) ?></span>
            <button type="button" class="vp-filter-clear ms-auto"
                    data-vp-filter-clear>
                <?= __('Clear') ?>
            </button>
        </div>

        <?php
        /*
         * **Not *no occurrence has this type*.** That was the wording
         * until phase 31 and it was a claim about the value made from a
         * sample of it — false on any value whose rows of that type are
         * all older than the eight this card drew. The banner chip that
         * did the narrowing carries the real count, and the full table
         * is one press away, so the empty state says which of the two it
         * is talking about and sends the reader to the other.
         */
        ?>
        <div class="vp-empty d-none" data-vp-filter-empty>
            <span class="misp-icon misp-icon-attribute misp-simple"></span>
            <span><?= sprintf(
                __('None of the occurrences shown here has type %s.'),
                '<span class="font-monospace" data-vp-filter-type></span>'
            ) ?></span>
            <a href="#tab-occurrences" class="vp-filter-clear">
                <?= __('Open the full table') ?>
            </a>
        </div>

        <div class="card-body p-0" data-vp-occ-table>
            <?= $this->element(
                'genericElementsBS5/IndexTable/index_table',
                array(
                    'scaffold_data' => array(
                        'data' => array(
                            'data' => $rows,
                            'fields' => $fields,
                            'primary_id_path' => 'Attribute.id',
                            'table_class' => 'ai-table vp-occ-table',
                            'row_class_callable' => $rowClass,
                        ),
                    ),
                )
            ) ?>
        </div>
    <?php endif; ?>

    <?php
    /*
     * **The multi-select toolbar was here and phase 31 withdrew it.**
     * Six mass actions, every one of them rendered disabled, under a
     * sample of eight rows nobody chose — a reader selecting rows here
     * could only ever have selected eight of a value's twenty-six, and
     * the toolbar under them offered nothing to do with the selection.
     * It is the Occurrences tab's control, where the rows are all
     * present, sortable and paged, and it is still there.
     *
     * Gone rather than disabled, on the same rule that removed the
     * pivot rail in phase 29: an inert control is an unfinished promise
     * to an analyst (D23). It took this element's last write control
     * and its `$noWrites` string with it.
     */
    ?>
</div>
