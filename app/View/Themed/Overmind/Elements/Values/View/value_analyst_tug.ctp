<?php
/**
 * The tug-bar — how many opinions fall each way.
 *
 * One stacked bar sized by *how many opinions fall each side of 50*,
 * with what it amounts to stated beside it in words. It answers "is
 * this set divided, and how lopsided" before the reader looks at a
 * single row, which is why it opens the Collaboration tab's standing
 * panel and why phase 35 brought it to the Overview.
 *
 * **Extracted from `value_analyst_standing` rather than copied.** Two
 * renderings of one encoding is exactly how the histogram this panel
 * deleted came to paint the axis the opposite way round from the table
 * beside it (`26-analyst.md` §6). One element cannot disagree with
 * itself, and the two callers hand it the same array from the same
 * union: `analystContext` builds `standing` once and both
 * `forAnalystStanding` and `forAnalystPreview` return it.
 *
 * **Sized by headcount, and it says so under itself.** The caption is
 * not decoration. On the standing panel the bar sits above a 0-100
 * score axis and a one-against-three split would otherwise put a
 * segment boundary at 25% of a scale it has nothing to do with; on the
 * Overview there is no axis, and the guard is against the plainer
 * misreading that a long green segment means a strong opinion rather
 * than several of them.
 *
 * **`tugLead` carries the denominator where the panel's own header
 * does not.** The standing panel's sub-line already reads *N opinions
 * from M organisations*, so its lead is just *The split*. The
 * Overview's card is headed *2 notes · 4 opinions · 1 proposal*, and
 * those opinions are not this bar's: `analystCounts` counts top-level
 * items of any anchor, `analystStanding` counts opinions at any depth
 * that rate the value. The two can differ in both directions, so the
 * caller that cannot rely on its header states the count in the lead.
 *
 * @var array $tugOrgs One row per opinion on the value — `standing`'s
 *                     `orgs`, from `ValueIntelligence::analystStanding`
 * @var string $tugLead The subhead over the bar
 */
$tugLead = isset($tugLead) ? $tugLead : __('The split');

/**
 * Which way an opinion argues, named for what the reader is told
 * rather than for the row's own `malicious` / `benign`.
 *
 * MISP's scale runs from disagreement to agreement with what the value
 * asserts, so an opinion above 50 is the *agreeing* one and takes the
 * green used for agreement everywhere on this page.
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
 * The split, counted off the rows handed in. Nothing else computes it,
 * so nothing else can disagree with it.
 */
$bySide = array('agree' => 0, 'dispute' => 0, 'neither' => 0);
foreach ($tugOrgs as $org) {
    $bySide[$sideOf($org['reads'])]++;
}
$total = count($tugOrgs);

/*
 * What the bar amounts to, in one clause, so a reader who has taken in
 * neither the bar nor the rows under it still has the answer.
 */
if ($bySide['dispute'] === 0) {
    $verdict = __('every opinion agrees');
} elseif ($bySide['agree'] === 0) {
    $verdict = __('every opinion disputes');
} elseif ($bySide['agree'] === $bySide['dispute']) {
    $verdict = sprintf(
        __('an even split, %s each way'),
        $bySide['agree']
    );
} else {
    $minor = min($bySide['agree'], $bySide['dispute']);
    $verdict = sprintf(
        $bySide['agree'] > $bySide['dispute']
            ? __n(
                'most agree; %d opinion of %d does not',
                'most agree; %d opinions of %d do not',
                $minor
            )
            : __n(
                'most dispute; %d opinion of %d does not',
                'most dispute; %d opinions of %d do not',
                $minor
            ),
        $minor,
        $total
    );
}

$segments = array(
    array('dispute', $bySide['dispute'], __('dispute')),
    array('neither', $bySide['neither'], __('neither')),
    array('agree', $bySide['agree'], __('agree')),
);
?>
<div class="vpa-tugblock">
    <div class="vpa-tuglead">
        <span class="vp-subhead mb-0"><?= h($tugLead) ?></span>
        <span class="vpa-verdict"><?= h($verdict) ?></span>
    </div>

    <div class="vpa-tug">
        <?php foreach ($segments as $segment):
            if ($segment[1] === 0) {
                continue;
            }
            $width = round($segment[1] / $total * 100, 3);
            ?>
            <div class="vpa-tug-seg vpa-s-<?= $segment[0] ?><?=
                      $segment[0] === 'agree' ? ' vpa-tug-end' : ''
                  ?>"
                 style="width: <?= $width ?>%;"
                 title="<?= h(sprintf(
                     __n(
                         '%1$d opinion %2$s',
                         '%1$d opinions %2$s',
                         $segment[1]
                     ),
                     $segment[1],
                     $sideWord($segment[0])
                 )) ?>">
                <?php if ($segment[0] === 'agree'): ?>
                    <span><?= h($segment[2]) ?></span>
                    <span class="vpa-tug-n"><?= (int)$segment[1] ?></span>
                <?php else: ?>
                    <span class="vpa-tug-n"><?= (int)$segment[1] ?></span>
                    <span><?= h($segment[2]) ?></span>
                <?php endif; ?>
            </div>
        <?php endforeach; ?>
    </div>

    <div class="vpa-tug-cap">
        <span><?= __('disputes') ?></span>
        <span><?= __('sized by number of opinions, not by score') ?></span>
        <span><?= __('agrees') ?></span>
    </div>
</div>
