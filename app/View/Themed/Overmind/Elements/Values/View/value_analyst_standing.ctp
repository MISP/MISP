<?php
/**
 * Where the organisations stand on this value.
 *
 * The panel opens on the split rather than on a summary of it. A mean
 * over a divided set is a reading nobody holds, and the Verdict tab
 * already says so about the same numbers; leading with an average here
 * would undo that one tab later.
 *
 * Two objects, in the order a card is scanned (`05-analyst.md` §16.3):
 *
 * 1. The tug-bar — one stacked bar sized by *how many opinions fall
 *    each way*, with the split stated beside it in words. It answers
 *    "is this set divided, and how lopsided" before the reader looks
 *    at a single row. Drawn by `value_analyst_tug` since phase 35,
 *    which the Overview's Analyst data card includes off the same
 *    `standing` array.
 * 2. The ledger — one row per opinion on a shared 0-100 lane, an
 *    organisation's rows together. A bar grows from the 50 pivot to
 *    that opinion's score, so direction is the side and length is the
 *    conviction, and the empty middle is a shaded column crossing
 *    every lane.
 *
 * **A row is an opinion, and phase 26 changed it from an
 * organisation.** The lane-per-organisation shape assumed an
 * organisation holds one position; the campaign's own default value
 * carries four opinions and all four are ADMIN's — 100, 100, 80, then
 * 10. Collapsed to one lane that value drew a single disputing
 * organisation over a set that is three-quarters agreement.
 * `26-analyst.md` §6.3.
 *
 * The two are deliberately not the same width. The tug-bar spans the
 * panel's whole padded width while the ruler and lanes stay inset in
 * their own grid column, because the bar is sized by headcount and the
 * lane axis by score: stack them flush and a one-against-three split
 * puts a segment boundary at 25% of the axis, which reads as "the set
 * divides at 25". The name column and the three trailing columns inset
 * the lane asymmetrically, so the two centres cannot coincide. The
 * caption under the bar states the units as the second guard.
 *
 * There is no histogram. Ten bands over three or four opinions is a
 * chart of almost nothing, and it was the one place on this panel that
 * painted the axis the other way round — below 50 green — against the
 * badges beside it. Each score is now drawn once, as a position, and
 * said once, as a numeral.
 *
 * Every number here is computed at render — MISP stores no mean, no
 * buckets and no per-organisation rollup anywhere (`05-analyst.md`
 * §11) — which is what the header chip says out loud.
 *
 * Lazily loaded into `.ajax-tab-content` from
 * ValuesController::viewAnalystStanding.
 *
 * @var array $valueIntelligence
 */
$analyst = $valueIntelligence['analyst'];
$standing = $analyst['standing'];
$orgs = $standing['orgs'];
$aggregate = $standing['aggregate'];

/**
 * Which way an opinion argues, named for what the reader is told
 * rather than for the engine's own `malicious` / `benign`.
 *
 * The indirection is worth removing rather than carrying: MISP's scale
 * runs from disagreement to agreement with what the value asserts, so
 * an opinion above 50 is the *agreeing* one and takes the green the
 * Overview card uses for agreement. Mapping `malicious` to a green
 * token two hops away is how the deleted histogram came to disagree
 * with the table beside it.
 *
 * @param string $reads malicious | benign | none
 * @return string agree | dispute | neither
 */
$sideOf = function ($reads) {
    if ($reads === 'malicious') {
        return 'agree';
    }
    if ($reads === 'benign') {
        return 'dispute';
    }
    return 'neither';
};

$sideWord = function ($side) {
    if ($side === 'agree') {
        return __('agrees');
    }
    if ($side === 'dispute') {
        return __('disputes');
    }
    return __('takes no side');
};

/*
 * How long ago, in the coarsest unit that is still true. An opinion
 * held for three months and one held yesterday are different evidence,
 * and the built panel rendered both as the same plain date.
 */
$staleAfter = 60;

$ageLabel = function ($days) {
    if ($days === null) {
        return null;
    }
    if ($days <= 0) {
        return __('today');
    }
    if ($days === 1) {
        return __('yesterday');
    }
    if ($days < 31) {
        return sprintf(__n('%d day ago', '%d days ago', $days), $days);
    }
    $months = (int)round($days / 30.44);
    $months = max(1, $months);
    return sprintf(
        __n('%d month ago', '%d months ago', $months),
        $months
    );
};

/*
 * The five band words, and where each one sits. MISP splits them at
 * 20/40/60/80 while the reading splits at 50, which is why a band word
 * is never coloured on this panel: `Neutral` covers 41-60 and so lands
 * on both sides of the pivot. The footnote says so.
 */
$bands = array(
    array(0, 20, __('Strongly disagree')),
    array(20, 40, __('Disagree')),
    array(40, 60, __('Neutral')),
    array(60, 80, __('Agree')),
    array(80, 100, __('Strongly agree')),
);

/**
 * One sortable token per column, so ordering compares what the column
 * means rather than what its cell happens to read.
 *
 * Cell text would not do it: the opinion is drawn as a position and
 * not written in its own column, `9` sorts above `85` as text, and the
 * reading is three words with an order (`disputes`, `neither`,
 * `agrees`) that none of them expresses. Every token is a string built
 * to sort lexicographically — the convention `value_occurrence_table`
 * and `value_sighting_list` already use — so the script needs one
 * comparison and no per-column knowledge.
 *
 * @param array $org
 * @param int $index Position in the order the server sent
 * @return string Attributes, ready to interpolate
 */
$pad = function ($number, $width = 4) {
    return str_pad((string)(int)$number, $width, '0', STR_PAD_LEFT);
};

$sideRank = array('dispute' => 0, 'neither' => 1, 'agree' => 2);

$rowSort = function ($org, $index) use ($sideOf, $pad, $sideRank) {
    $score = (int)$org['score'];
    $side = $sideOf($org['reads']);
    $data = array(
        'vp-sort-org' => mb_strtolower($org['org']),
        'vp-sort-score' => $pad($score, 3),
        /*
         * Side first, then score inside it: a reader grouping by the
         * reading still wants the strongest of each group at its end,
         * and low-to-high matches the axis the lanes are drawn on.
         */
        'vp-sort-reading' => $sideRank[$side] . $pad($score, 3),
        'vp-sort-notes' => $pad($org['notes']),
        'vp-sort-activity' => empty($org['last'])
            ? ''
            : date('YmdHi', strtotime($org['last'])),
        /*
         * The row's position in the order the server sent — by
         * opinion, highest first. Reordering moves the rows
         * themselves, so the third click has to restore this rather
         * than merely stop comparing.
         */
        'vp-sort-default' => $pad($index),
    );
    $out = '';
    foreach ($data as $key => $value) {
        $out .= ' data-' . $key . '="' . h($value) . '"';
    }
    return $out;
};

/**
 * Where a lane's score numeral goes.
 *
 * **Outward from the dot** — away from the pivot — by default, because
 * that is the free side of a bar growing from 50 and it puts the number
 * at the end of the thing it measures.
 *
 * **Except near the ends of the axis, where outward is off the lane.**
 * At 100 the numeral was placed 13px past the lane's right edge, and
 * the grid gap to the next column is 8px — so on `8.8.8.8` the `100`
 * sat on top of the word *agrees* in the *Reads it as* cell, 34px
 * outside its own lane. Near either end the numeral now flips to the
 * inward side of the dot and takes a backing, because inward means over
 * its own bar and `--vpa-side-ink` on `--vpa-side` is one hue on
 * itself.
 *
 * **The thresholds are derived rather than guessed.** `.vpa-ledger`'s
 * lane column is `minmax(320px, 1fr)`, so 320px is the narrowest the
 * lane ever gets — below that the ledger scrolls instead of shrinking.
 * The numeral needs its 13px offset plus its own width, and it is
 * monospace with `tabular-nums`: 3ch ≈ 21px at three digits, 2ch ≈ 14px
 * at two. 34px of 320px is 10.7% of the axis and 27px is 8.5%, which is
 * what puts the flip at 88 and at 12 rather than at a rounder pair.
 * The asymmetry is the third digit.
 *
 * A clamp was the other option and is worse: pinning the numeral at the
 * lane's edge leaves the dot to walk over it between 96 and 100, which
 * trades a collision with the next column for a collision with the mark
 * the numeral is labelling.
 *
 * @param int $score
 * @return array style string, then the class suffix for a flipped one
 */
$lanePlacement = function ($score) {
    $outwardIsRight = $score >= 50;
    $flip = $score >= 88 || $score <= 12;
    /*
     * `left` anchors the numeral to the right of the dot and `right`
     * anchors it to the left, so which property is used is the outward
     * side XOR the flip.
     */
    $useLeft = $outwardIsRight !== $flip;
    return array(
        $useLeft
            ? 'left: calc(' . $score . '% + 13px);'
            : 'right: calc(' . (100 - $score) . '% + 13px);',
        $flip ? ' vpa-lane-val-in' : '',
    );
};

/**
 * A sortable heading. A real button, so it is reachable and operable
 * from the keyboard, carrying MISP's own `sortable-header`/`sort-icon`
 * so a sortable heading here looks like one anywhere else.
 *
 * @param string $key Column key, matching the row's `vp-sort-<key>`
 * @param string $label
 * @return string
 */
$sortBtn = function ($key, $label) {
    return '<button type="button" class="vp-th-sort"'
        . ' data-vp-sort-col="' . h($key) . '">'
        . '<span class="sortable-header">' . h($label)
        . '<i class="sort-icon"></i></span></button>';
};

$subtitle = $aggregate === null
    ? h(__('No opinion on this value from any organisation'))
    : h($aggregate['note']);

/*
 * The chip is a statement about numbers on the panel, so a panel with
 * no numbers on it does not get to make it.
 */
$headerExtra = $aggregate === null ? null
    : '<span class="badge bg-body-tertiary text-body-secondary'
        . ' border fw-normal" title="'
        . h(__(
            'MISP computes no mean, no distribution and no'
            . ' per-organisation rollup over analyst data. Every number'
            . ' on this panel is derived from the opinions themselves'
            . ' when the page is built.'
        )) . '">' . h(__('computed at render')) . '</span>';
?>
<div class="card shadow-sm mb-3 vp-panel vp-dense"
     style="--vp-panel-color: var(--analystData);"
     data-vp-analyst-standing>

    <?= $this->element('Values/View/value_panel_header', array(
        'panelTitle' => __('Where the organisations stand'),
        'panelIcon' => 'fas fa-arrows-left-right-to-line',
        'panelColor' => 'var(--analystData)',
        'panelSub' => $subtitle,
        'panelExtra' => $headerExtra,
    )) ?>

    <?php if ($aggregate === null): ?>
        <div class="vp-empty">
            <i class="fas fa-arrows-left-right-to-line"></i>
            <span><?=
                __('No organisation has recorded an opinion on this value.')
            ?></span>
        </div>
    <?php else: ?>
        <?php
        $gap = $aggregate['gap'];
        $showGap = $gap !== null && $gap['points'] >= 20;
        ?>
        <div class="p-3">

            <?php
            /*
             * --------------------------------------------------------
             * The tug-bar
             * --------------------------------------------------------
             * Full panel width, and never aligned to the lane axis
             * below it — see the note at the head of this file.
             *
             * Its own element since phase 35, because the Overview's
             * Analyst data card draws the same bar off the same
             * `standing` array. No lead is passed: this panel's
             * sub-line already reads *N opinions from M
             * organisations*, so the default *The split* is not
             * carrying a denominator anybody is missing.
             */
            ?>
            <?= $this->element('Values/View/value_analyst_tug', array(
                'tugOrgs' => $orgs,
            )) ?>

            <?php
            /*
             * --------------------------------------------------------
             * The ledger
             * --------------------------------------------------------
             * A flat grid: five cells in the header row and five per
             * opinion, with the void, the pivot and the mean
             * drawn inside each lane. They are per-lane rather than
             * one element spanning the rows because an explicitly
             * placed child in an otherwise auto-placed grid displaces
             * every cell after it; adjacent lanes stack the slices
             * into one continuous column anyway.
             */
            $aria = array();
            foreach ($orgs as $org) {
                $aria[] = sprintf(
                    __('%1$s at %2$s'),
                    $org['org'],
                    $org['score']
                );
            }
            ?>
            <div class="vpa-ledger-scroll">
                <div class="vpa-ledger"
                     data-vp-a-ledger
                     role="group"
                     aria-label="<?= h(sprintf(
                         __('Every opinion on the 0 to 100 scale, with'
                             . ' the organisation that wrote it: %s.'),
                         implode(__(', '), $aria)
                     )) ?>">

                    <div class="vpa-h"><?=
                        $sortBtn('org', __('Organisation'))
                    ?></div>

                    <?php
                    /*
                     * The lane column's heading sits inside the ruler,
                     * because the ruler *is* that column's header —
                     * and the opinion is the one column whose values
                     * are drawn rather than written, so without a
                     * heading of its own it would be the only column
                     * a reader could not sort by.
                     */
                    ?>
                    <div class="vpa-ruler">
                        <?= $sortBtn('score', __('Opinion')) ?>
                        <?php foreach ($bands as $b => $band):
                            $edge = '';
                            $at = ($band[0] + $band[1]) / 2;
                            if ($b === 0) {
                                $edge = ' vpa-edge-l';
                                $at = 0;
                            } elseif ($b === count($bands) - 1) {
                                $edge = ' vpa-edge-r';
                                $at = 100;
                            }
                            ?>
                            <span class="vpa-ruler-band<?= $edge ?>"
                                  style="left: <?= $at ?>%;"><?=
                                h($band[2])
                            ?></span>
                        <?php endforeach; ?>

                        <?php foreach (array(0, 25, 50, 75, 100) as $tick):
                            $edge = '';
                            if ($tick === 0) {
                                $edge = ' vpa-edge-l';
                            } elseif ($tick === 100) {
                                $edge = ' vpa-edge-r';
                            }
                            ?>
                            <span class="vpa-ruler-tick<?= $edge ?>"
                                  style="left: <?= $tick ?>%;"><?=
                                $tick
                            ?></span>
                        <?php endforeach; ?>

                        <?php if ($showGap): ?>
                            <span class="vpa-ruler-void"
                                  style="left: <?=
                                      ($gap['from'] + $gap['to']) / 2
                                  ?>%;"><?= h(sprintf(
                                __n(
                                    'no opinion falls in this %d point',
                                    'no opinion falls in these %d points',
                                    $gap['points']
                                ),
                                $gap['points']
                            )) ?></span>
                        <?php endif; ?>
                    </div>

                    <div class="vpa-h"><?=
                        $sortBtn('reading', __('Reads it as'))
                    ?></div>
                    <div class="vpa-h vpa-r"><?=
                        $sortBtn('notes', __('Notes'))
                    ?></div>
                    <div class="vpa-h vpa-r"><?=
                        $sortBtn('activity', __('Last activity'))
                    ?></div>

                    <?php foreach ($orgs as $index => $org):
                        $side = $sideOf($org['reads']);
                        $score = (int)$org['score'];
                        $from = min(50, $score);
                        $to = max(50, $score);
                        $days = isset($org['days']) ? $org['days'] : null;
                        $stale = $days !== null && $days >= $staleAfter;
                        ?>
                        <div class="vpa-row"
                             data-vp-a-org="<?= h($org['org']) ?>"<?=
                             $rowSort($org, $index) ?>>

                            <div class="vpa-cell vpa-org">
                                <span class="misp-icon
                                             misp-icon-organisation
                                             misp-simple"></span>
                                <span class="vp-min-w-0 text-truncate">
                                    <?php
                                    /*
                                     * Linked where the organisation
                                     * still resolves — null on a row
                                     * whose `orgc_uuid` names one that
                                     * no longer exists, which has no
                                     * name to print either.
                                     */
                                    ?>
                                    <?php if (empty($org['org_id'])): ?>
                                        <?= h($org['org']) ?>
                                    <?php else: ?>
                                        <a class="vpa-orglink"
                                           href="<?= h($baseurl)
                                               ?>/organisations/view/<?=
                                               (int)$org['org_id'] ?>"><?=
                                            h($org['org'])
                                        ?></a>
                                    <?php endif; ?>
                                </span>
                            </div>

                            <div class="vpa-lane vpa-s-<?= $side ?>"
                                 title="<?= h(sprintf(
                                     __('%1$s · %2$s/100 · %3$s'),
                                     $org['org'],
                                     $score,
                                     $org['label']
                                 )) ?>">
                                <?php if ($showGap): ?>
                                    <span class="vpa-lane-void"
                                          style="left: <?= $gap['from'] ?>%;
                                                 right: <?=
                                                     100 - $gap['to']
                                                 ?>%;"></span>
                                <?php endif; ?>
                                <span class="vpa-lane-pivot"
                                      style="left: 50%;"></span>
                                <span class="vpa-lane-mean"
                                      style="left: <?=
                                          $aggregate['mean']
                                      ?>%;"></span>
                                <span class="vpa-lane-track"></span>
                                <span class="vpa-lane-bar"
                                      style="left: <?= $from ?>%;
                                             right: <?= 100 - $to ?>%;"></span>
                                <span class="vpa-lane-dot"
                                      style="left: <?= $score ?>%;"></span>
                                <?php
                                list($valStyle, $valFlip) =
                                    $lanePlacement($score);
                                ?>
                                <span class="vpa-lane-val<?= $valFlip ?>"
                                      style="<?= $valStyle
                                      ?>"><?= $score ?></span>
                            </div>

                            <div class="vpa-cell">
                                <span class="vpa-reading vpa-s-<?= $side ?>">
                                    <i></i><?= h($sideWord($side)) ?>
                                </span>
                                <span class="vpa-band"><?=
                                    h($org['label'])
                                ?></span>
                            </div>

                            <div class="vpa-cell vpa-r font-monospace"><?=
                                $org['notes'] > 0
                                    ? (int)$org['notes']
                                    : '<span class="text-body-secondary">'
                                        . '&mdash;</span>'
                            ?></div>

                            <div class="vpa-cell vpa-r">
                                <span class="vpa-age<?=
                                          $stale ? ' vpa-age-stale' : ''
                                      ?>"
                                      title="<?= h($org['last']) ?>">
                                    <?php if ($stale): ?>
                                        <i class="vpa-age-dot"></i>
                                    <?php endif; ?>
                                    <?= h($days === null
                                        ? $org['last']
                                        : $ageLabel($days)) ?>
                                </span>
                            </div>

                        </div>
                    <?php endforeach; ?>

                </div>
            </div>

            <?php
            /*
             * The aggregate, as a row of chips rather than a headline.
             * The mean keeps `.vpa-mean`, so it is struck through here
             * on exactly the values where it describes nobody.
             */
            ?>
            <div class="vpa-stats">
                <span class="vpa-stat">
                    <b><?= count($aggregate['clusters']) ?></b>
                    <?= h(__n(
                        'position',
                        'positions',
                        count($aggregate['clusters'])
                    )) ?>
                </span>

                <?php if ($showGap): ?>
                    <span class="vpa-stat vpa-stat-void">
                        <b><?= (int)$gap['points'] ?></b>
                        <?= __('points of empty middle') ?>
                    </span>
                <?php endif; ?>

                <span class="vpa-stat">
                    <b><?= (int)$aggregate['empty_bands'] ?></b>
                    <?= __('of ten bands unoccupied') ?>
                </span>

                <span class="vpa-mean<?= $aggregate['mean_orphan']
                          ? ' vpa-mean-orphan' : '' ?>"
                      title="<?= h($aggregate['mean_orphan']
                          ? __(
                              'Shown because the aggregate is specified,'
                              . ' struck through because it describes'
                              . ' nobody: the nearest opinion is more'
                              . ' than half a band away.'
                          )
                          : __(
                              'Shown because the aggregate is specified.'
                              . ' On this value an opinion does sit'
                              . ' within half a band of it.'
                          )) ?>">
                    <span class="vpa-mean-value"><?=
                        h($aggregate['mean_label'])
                    ?></span>
                    <span><?= h($aggregate['mean_orphan']
                        ? __('mean — nobody holds it')
                        : __('mean')) ?></span>
                </span>
            </div>

            <p class="vp-aside-note"><?= __(
                'Above 50 agrees with what the value asserts; below 50'
                . ' disputes it — the same hues the Overview card uses'
                . ' for the bands it names. The band word is MISP\'s own'
                . ' five-step scale and splits at 20/40/60/80, so a'
                . ' Neutral opinion can sit on either side of the pivot:'
                . ' 45 disputes, 60 agrees. An opinion written on a note'
                . ' rates the note, not the value, and is not counted'
                . ' here.'
            ) ?></p>

        </div>
    <?php endif; ?>

    <?php
    /*
     * §14.6's third computed-judgement panel.
     *
     * The rule, after phase 23 found the second: a panel that renders a
     * *computed judgement* carries a permanent caveat; a panel that
     * renders a count does not — and the contract predicted that a
     * later phase computing rather than counting would add the third.
     * This is it. The mean, the buckets, the empty band and every lane
     * above are derived from the opinions **this** reader may see, and
     * `AnalystData::buildConditions` scopes that set per reader, so two
     * colleagues can read different means off the same value on the
     * same afternoon.
     *
     * Always shown, on every value, identical for every reader —
     * including values with nothing hidden. A line that never varies
     * carries no information about what any particular reader cannot
     * see, which is exactly what separates it from the withheld-count
     * band §14.6 forbids. `26-analyst.md` D7.
     */
    ?>
    <p class="vp-acl-note">
        <i class="fas fa-user-shield"></i>
        <span><?= h(__(
            'Every number here is computed over the opinions you can'
            . ' see. Two readers whose analyst-data visibility differs'
            . ' can honestly read different positions for this value on'
            . ' the same afternoon.'
        )) ?></span>
    </p>

</div>
