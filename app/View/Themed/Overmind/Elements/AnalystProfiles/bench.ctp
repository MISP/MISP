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
 */
App::uses('ValueUrlTool', 'Tools/ValueIntelligence');
App::uses('ValueLean', 'Tools/ValueIntelligence');

$full = isset($full) ? $full : false;
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
/*
 * The editor and the viewer carry the document beside the bench, so
 * benching and pinning happen in place and the unsaved edits survive.
 * The expanded simulator is a page of its own with nothing unsaved,
 * and the same presses are a navigation there.
 */
$live = !$full;
$benchUrl = $this->Html->url(array(
    'action' => $this->request->params['action'], $profileId));
$pinUrl = function ($value, $pin) {
    return array('action' => $pin ? 'pin' : 'unpin',
        ValueUrlTool::encode($value));
};
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
    <?php
    /*
     * The picker, and it comes before everything including the empty
     * state. An instruction to pin a value with no control that pins
     * one is the state a reader who has not arrived from a value page
     * actually lands in, and it was a dead end.
     */
    ?>
    <div class="bench-pick">
        <div class="input-group input-group-sm">
            <input type="text" class="form-control form-control-sm"
                   data-ap-bench-input autocomplete="off" spellcheck="false"
                   placeholder="<?= h(__('try a value — an IP, a domain,'
                       . ' a hash')) ?>">
            <button type="button" class="btn btn-sm btn-outline-primary"
                    data-ap-bench=""><?= h(__('Try it')) ?></button>
        </div>
        <?php if (!empty($values)): ?>
            <div class="bench-quick">
                <span class="wb-sub"><?= h(__('yours:')) ?></span>
                <?php foreach ($values as $candidate): ?>
                    <button type="button"
                            class="chip <?= $candidate === $benched
                                ? 'is-on' : '' ?>"
                            data-ap-bench="<?= h($candidate) ?>"><?=
                        h($candidate) ?></button>
                <?php endforeach; ?>
            </div>
        <?php endif; ?>
    </div>

    <?php if ($benched === null): ?>
        <div class="wb-empty">
            <div class="fw-semibold"><?= h(__('No value chosen')) ?></div>
            <p class="mb-0 mt-1">
                <?= h(__('Put a value in the box above to see what this'
                    . ' profile makes of it, beside the profile in force.'
                    . ' Pin a value to keep it here on every profile you'
                    . ' open.')) ?>
            </p>
        </div>
    <?php else: ?>
        <div class="bench-value">
            <span class="v"><?= h($benched) ?></span>
            <?php if (!in_array($benched, $pinned, true)): ?>
                <span class="wb-sub"><?= h(__('not pinned')) ?></span>
                <?php if ($live): ?>
                    <button type="button" data-ap-value="<?= h($benched) ?>"
                            data-ap-pin="<?= h($this->Html->url(
                                $pinUrl($benched, true))) ?>"
                            class="btn btn-sm btn-outline-primary py-0 px-2">
                        <?= h(__('Pin')) ?>
                    </button>
                <?php else: ?>
                    <?php
                    /*
                     * No form to borrow a token from on this page, so
                     * the helper mints its own — a raw POST form here
                     * carries none and trips the CSRF check.
                     */
                    ?>
                    <?= $this->Form->postLink(__('Pin'),
                        $pinUrl($benched, true),
                        array('class' => 'btn btn-sm btn-outline-primary'
                            . ' py-0 px-2')) ?>
                <?php endif; ?>
            <?php else: ?>
                <span class="wb-sub"><?= h(__('pinned')) ?></span>
                <?php if ($live): ?>
                    <button type="button" data-ap-value="<?= h($benched) ?>"
                            data-ap-pin="<?= h($this->Html->url(
                                $pinUrl($benched, false))) ?>"
                            class="btn btn-sm btn-outline-secondary py-0 px-2">
                        <?= h(__('Unpin')) ?>
                    </button>
                <?php else: ?>
                    <?= $this->Form->postLink(__('Unpin'),
                        $pinUrl($benched, false),
                        array('class' => 'btn btn-sm btn-outline-secondary'
                            . ' py-0 px-2')) ?>
                <?php endif; ?>
            <?php endif; ?>
        </div>

        <div class="bench-live">
            <?= h(__('recomputed')) ?>
        </div>

        <?php if ($detail !== null): ?>
            <div class="bench-sec">
                <span><?= h(__('Assessment')) ?></span>
            </div>
            <?= $this->element('AnalystProfiles/assessment_head', array(
                'axes' => $detail['axes'],
                'moved' => $detail['changed'],
                /*
                 * The benched value's dates, for the provenance table
                 * under the relevance line. Absent on a bench with no
                 * value, and the element draws nothing then.
                 */
                'dates' => $bench['dates'] ?? null,
                'lastSighting' => $benchSightingLast,
                'sightingTotal' => 0,
            )) ?>

            <div class="bench-sec">
                <span><?= h(__('Signal strength')) ?></span>
            </div>
            <div class="bench-q">
                <span class="now"><?= h($detail['totals']['after']) ?></span>
                <span class="from">
                    <?= h(__('signal strength')) ?><br>
                    <span class="num"><?= h($detail['totals']['before']) ?></span>
                    <?= h(__('under the profile in force')) ?>
                </span>
                <span class="num <?= $detail['totals']['delta'] > 0
                        ? 'd-up'
                        : ($detail['totals']['delta'] < 0 ? 'd-dn' : 'd-0') ?>"
                      style="font-size:1.1rem;font-weight:700;margin-left:auto">
                    <?= h($detail['totals']['delta'] > 0
                        ? '+' . $detail['totals']['delta']
                        : $detail['totals']['delta']) ?>
                </span>
            </div>

            <?= $this->element('AnalystProfiles/block_strip', array(
                'strip' => $bands,
                'marks' => array(
                    'was' => $detail['totals']['before'],
                    'now' => $detail['totals']['after'],
                ),
            )) ?>

            <div class="bench-axes bench-meta">
                <div>
                    <span><?= h(__('signals fired')) ?></span>
                    <b class="num"><?= h($detail['axes']['fired']['after']) ?></b>
                </div>
                <div>
                    <span><?= h(__('highest reachable')) ?></span>
                    <b class="num"><?= h($bands['bound']) ?></b>
                </div>
            </div>

            <?php $rule = $detail['axes']['rule']['after']; ?>
            <?php if (!empty($rule)): ?>
                <div class="wb-note warn mt-2">
                    <b><?= h($detail['axes']['lean']['after']) ?></b>
                    &mdash; <?= h($rule['prose']) ?>
                    <?php if (!empty($rule['evidence'])): ?>
                        <div class="wb-sub mt-1"><?= h($rule['evidence']) ?></div>
                    <?php endif; ?>
                </div>
            <?php endif; ?>

            <div class="bench-sec" style="margin-top:1.1rem">
                <span><?= $full
                    ? h(__('Every ledger row'))
                    : h(__('What moved')) ?></span>
                <span class="num"><?= h(sprintf(
                    __('%1$s of %2$s rows'),
                    count($detail['moved']),
                    count($detail['rows'])
                )) ?></span>
            </div>
            <?= $this->element('AnalystProfiles/diff_table', array(
                'detail' => $detail,
                'full' => $full,
            )) ?>
        <?php endif; ?>

        <?= $this->element('AnalystProfiles/comparison', array(
            'comparison' => $bench['comparison'],
            'pinned' => $pinned,
        )) ?>
    <?php endif; ?>

    <?php if (!$full): ?>
        <a class="btn btn-sm btn-outline-primary w-100 mt-3"
           href="<?= h($this->Html->url(array(
               'action' => 'simulate',
               $profileId,
               '?' => $focus === null
                   ? array()
                   : array('value' => ValueUrlTool::encode($focus)),
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
