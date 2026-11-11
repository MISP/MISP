<?php
/**
 * The right-hand pane: what the candidate does to a real value.
 *
 * This is the whole bet of the design. MISP already shipped a
 * simulator nobody used, and a simulator that is a destination is a
 * simulator that is not used — so the bench is half the editor and
 * cannot be skipped. It is the same computation the `simulate` page
 * gives the whole width to, which is why both read one payload.
 *
 * It computes and it writes nothing, and it says so.
 *
 * @var array $bench The simulation: base, in_force, detail, comparison
 * @var bool $full Every ledger row, or only the rows that moved
 * @var array $bands
 * @var string $profileId
 * @var bool $modal Read in #mainModal: no picker, no pinning, no link out
 */
App::uses('ValueLean', 'Tools/ValueIntelligence');

$full = isset($full) ? $full : false;
$modal = !empty($modal);
$detail = $bench['detail'];
/*
 * The newest sighting, for the dates table's `Sighting.date_sighting`
 * row. It comes off the clock's own events rather than from a second
 * query the bench does not otherwise need.
 *
 * **The count does not, and the bench shows none.** The clock folds
 * sightings to one entry a day and caps them, so counting those events
 * gave `14 sightings` under a value page reading `53` — a number that
 * is not wrong about anything so much as about nothing, since it counts
 * days the clock kept. A date with no count is honest; a count that
 * disagrees with the other pane is not.
 */
$benchSightingLast = null;
$benchClock = $detail !== null
    && isset($detail['axes']['relevance']['runway']['clock']['events'])
        ? $detail['axes']['relevance']['runway']['clock']['events']
        : array();
foreach ($benchClock as $event) {
    if (!in_array($event['kind'], array('sighting', 'foreign_sighting'),
        true)
    ) {
        continue;
    }
    if ($benchSightingLast === null
        || (int)$event['at'] > $benchSightingLast
    ) {
        $benchSightingLast = (int)$event['at'];
    }
}
$focus = $bench['focus'];
$values = $bench['values'];
$pinned = $bench['comparison_set'];
$benched = !empty($values) ? $values[0] : null;
// Where the simulate page's picker navigates to, with `?value=`.
$benchUrl = $this->Html->url(array(
    'action' => $this->request->params['action'], $profileId));
/*
 * Which way the direction pair points, re-stated on every recompute.
 * `--vp-dir-with` is *with the lean*, and a weight edit can move the
 * lean itself — a **lean** ledger that sums against the lean it was
 * anchored to comes back `contested` (`review-2026-09-13.md` §A2; it
 * used to be the whole ledger, which is why an ordinary thin record
 * tripped it) — so the swap has to arrive with the fragment rather
 * than being set once on the page around it.
 */
$leanNow = $detail !== null && isset($detail['axes']['lean']['after'])
    ? $detail['axes']['lean']['after']
    : null;
$directionStyle = $leanNow === null
    ? ''
    : ValueLean::directionStyle($leanNow);
/*
 * What the signals pane needs to catch up.
 *
 * The recompute answers this fragment and nothing else, so the
 * contribution column beside it used to keep whatever the page loaded
 * with — a confident `+7` next to a signal strength that had just moved to 48.
 * The numbers ride back with the fragment and the editor writes them
 * into the cells; the labels come too, because the column's wording is
 * translated and the script has no business holding a copy.
 */
$ledgerNow = array();
if ($detail !== null) {
    foreach ($detail['rows'] as $row) {
        if ($row['after'] !== null) {
            $ledgerNow[$row['id']] = (int)$row['after'];
        }
    }
}
$carry = array(
    'benched' => $benched !== null,
    'direction' => $directionStyle,
    /*
     * `block_items.ctp`'s caption, which the recompute rewrites — so
     * the two have to say the same thing or the label changes on the
     * first edit. It stopped naming the lean with §D1; what is left
     * varying is whether there is a ledger to caption at all.
     */
    'anchor' => $leanNow !== null && $leanNow !== 'none'
        ? __('+ carries it')
        : '',
    'labels' => array(
        'none' => "—",
        'no_row' => __('did not fire'),
        'no_row_sub' => '',
    ),
    'rows' => $ledgerNow,
);
?>
<div class="wb-bench-inner" data-ap-bench-url="<?= h($benchUrl) ?>"
     data-ap-ledger="<?= h(json_encode($carry)) ?>"
     <?= $directionStyle === ''
         ? '' : 'style="' . h($directionStyle) . '"' ?>>
    <?php if ($benched === null): ?>
        <div class="wb-empty">
            <div class="fw-semibold"><?= h(__('No value chosen')) ?></div>
            <p class="mb-0 mt-1">
                <?= $modal
                    ? h(__('Try a value on the profile page, then open the'
                        . ' comparison again to read every row of it.'))
                    : h(__('Put a value in the box above to see what this'
                        . ' profile makes of it, beside the profile in force.'
                        . ' Pin a value to keep it here on every profile you'
                        . ' open.')) ?>
            </p>
        </div>
    <?php else: ?>
        <?php if ($detail !== null): ?>
            <?= $this->element('AnalystProfiles/compare_axes', array(
                'detail' => $detail,
                'dates' => $bench['dates'] ?? null,
                'lastSighting' => $benchSightingLast,
            )) ?>

            <section class="ap-cmp-card">
                <header class="ap-cmp-card-h">
                    <span class="ap-cmp-card-t"><?= h(__('Signal strength on the bands')) ?></span>
                    <span class="ap-cmp-card-aside"><?= h(sprintf(
                        __('signals fired %1$s → %2$s · highest reachable %3$s'),
                        $detail['axes']['fired']['before'], $detail['axes']['fired']['after'],
                        $bands['bound'])) ?></span>
                </header>
                <div class="ap-cmp-card-b">
                    <?= $this->element('AnalystProfiles/block_strip', array(
                        'strip' => $bands,
                        'marks' => array(
                            'was' => $detail['totals']['before'],
                            'now' => $detail['totals']['after'],
                        ),
                    )) ?>
                    <div class="ap-cmp-legend">
                        <span class="is-was"><span class="ap-key-dot" aria-hidden="true"></span><?=
                            h(__('in force')) ?> <b class="num"><?= h($detail['totals']['before']) ?></b></span>
                        <span class="is-now"><span class="ap-key-dot" aria-hidden="true"></span><?=
                            h(__('candidate')) ?> <b class="num"><?= h($detail['totals']['after']) ?></b></span>
                    </div>
                </div>
            </section>

            <section class="ap-cmp-card">
                <header class="ap-cmp-card-h">
                    <span class="ap-cmp-card-t"><?= h(__('What moves, row by row')) ?></span>
                    <span class="ap-cmp-card-aside"><?= h(sprintf(
                        __('%1$s of %2$s rows'),
                        count($detail['moved']),
                        count($detail['rows'])
                    )) ?></span>
                </header>
                <div class="ap-cmp-card-b">
                    <?= $this->element('AnalystProfiles/diff_table', array(
                        'detail' => $detail,
                    )) ?>
                </div>
            </section>
        <?php endif; ?>

        <?= $this->element('AnalystProfiles/comparison', array(
            'comparison' => $bench['comparison'],
            'pinned' => $pinned,
        )) ?>
    <?php endif; ?>

    <?php // Nothing to compare until a value is on the bench. ?>
    <?php if (!$full && $benched !== null): ?>
        <a class="btn btn-sm btn-outline-primary w-100 mt-3" data-ap-compare
           href="<?= h($this->Html->url(array(
               'action' => 'simulate',
               $profileId,
               '?' => $focus === null
                   ? array()
                   : array('value' => $focus),
           ))) ?>">
            <?= h(__('Open the full comparison')) ?>
        </a>
    <?php endif; ?>
</div>
<?php if (!empty($curveBlock) && !empty($curveSection)): ?>
    <?php
    /*
     * The TTL curve, redrawn from the posted document and riding back
     * with the bench.
     *
     * It belongs to the relevance section, not to this pane — but the
     * recompute is the only thing on this page that already knows what
     * the unsaved form says, and adding a second endpoint to redraw one
     * polyline would be a second request per keystroke for a figure
     * this one is regenerating anyway. The editor lifts it out of here
     * and drops it where it lives; this carrier is never displayed.
     */
    ?>
    <div hidden data-ap-curve>
        <?= $this->element('AnalystProfiles/ttl_curve', array(
            'block' => $curveBlock,
            'section' => $curveSection,
            'runway' => isset($curveRunway) ? $curveRunway : null,
        )) ?>
    </div>
<?php endif; ?>
