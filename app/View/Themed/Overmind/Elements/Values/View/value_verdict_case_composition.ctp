<?php
/**
 * How the two weights were reached, as a rail card.
 *
 * The arithmetic the agreeing layout shows for its signal strength, done over
 * the lean ledger instead and folded into two sides that are never
 * added together. Each case gets its own strip and its own total, so
 * the tug-of-war bar in the hero can be checked against the signals
 * that produced it.
 *
 * **The lean rows, not the signal strength's**, since `review-2026-09-13.md`
 * §A3: splitting the whole ledger by sign seated five absences under
 * a heading claiming they read the value as benign. So this card and
 * the agreeing layout's are no longer the same rows — that one sums
 * to `signal_strength`, this one to `lean_weight`, which is also why the two
 * totals here really are never the signal strength's difference.
 *
 * Grouped by signal group rather than listed per signal: at rail
 * width a signal's own wording does not fit, and "what kind of
 * evidence is carrying this case" is the question the breakdown
 * answers anyway.
 *
 * Derived from the cases rather than carried separately, so this card
 * and the two columns beside it cannot disagree.
 *
 * @var array $valueIntelligence
 */
$verdict = $valueIntelligence['verdict'];
$cases = $verdict['cases'] ?? array();

/*
 * One colour per group, shared across both cases, so the same group
 * is the same colour on both sides and the two strips can be compared.
 */
$groupColours = array(
    'var(--event)',
    'var(--sighting)',
    'var(--galaxy)',
    'var(--correlation)',
    'var(--type)',
    'var(--enrichment)',
);
$colourFor = array();
$next = 0;

$sides = array();
foreach ($cases as $case) {
    $byGroup = array();
    foreach ($case['rows'] as $row) {
        $group = $row['kind'];
        if (!isset($colourFor[$group])) {
            $colourFor[$group] = $groupColours[
                $next++ % count($groupColours)
            ];
        }
        if (!isset($byGroup[$group])) {
            $byGroup[$group] = 0;
        }
        $byGroup[$group] += (int)$row['points'];
    }
    arsort($byGroup);
    $sides[] = array(
        'side' => $case['side'],
        'title' => $case['title'],
        'total' => (int)$case['weight'],
        'segments' => $byGroup,
    );
}
?>
<?php if (!empty($sides)): ?>
    <div class="card shadow-sm mb-3 vp-panel vp-aside">

        <div class="vp-aside-head">
            <i class="fas fa-calculator"
               style="color: var(--enrichment);"></i>
            <span class="vp-aside-title">
                <?= h(sprintf(
                    __('How %1$s and %2$s were reached'),
                    $sides[0]['total'],
                    $sides[1]['total']
                )) ?>
            </span>
        </div>

        <div class="p-3 d-flex flex-column gap-3">

            <?php foreach ($sides as $s => $side):
                $span = max($side['total'], 1);
                ?>
                <div class="vp-case-comp vp-case-comp-<?=
                    $side['side'] === 'threat'
                        ? 'malicious'
                        : 'benign' ?>">

                    <div class="vp-case-comp-head">
                        <span class="vp-case-comp-title">
                            <?= h($side['title']) ?>
                        </span>
                        <span class="vp-case-comp-total">
                            <?= h($side['total']) ?>
                        </span>
                    </div>

                    <div class="vp-composition">
                        <?php foreach ($side['segments']
                            as $group => $points): ?>
                            <span class="vp-composition-seg"
                                  style="width: <?= round(
                                      $points / $span * 100,
                                      2
                                  ) ?>%; --vp-seg-color: <?=
                                      h($colourFor[$group]) ?>;"
                                  title="<?= h(sprintf(
                                      '%1$s +%2$s',
                                      $group,
                                      $points
                                  )) ?>"></span>
                        <?php endforeach; ?>
                    </div>

                    <div class="vp-comp-legend">
                        <?php foreach ($side['segments']
                            as $group => $points): ?>
                            <div class="vp-comp-row">
                                <span class="vp-comp-swatch"
                                      style="--vp-seg-color: <?=
                                          h($colourFor[$group]) ?>;">
                                </span>
                                <span class="vp-comp-name">
                                    <?= h($group) ?>
                                </span>
                                <span class="vp-comp-pts">
                                    +<?= h($points) ?>
                                </span>
                            </div>
                        <?php endforeach; ?>
                    </div>

                </div>
            <?php endforeach; ?>

            <p class="vp-comp-note">
                <?= __(
                    'The two totals are never added or subtracted. A'
                    . ' single number would be the mean of two'
                    . ' incompatible readings.'
                ) ?>
            </p>

            <?php /*
             * The same scope sentence the agreeing rail carries. This
             * card stands in for `value_verdict_composition` on a
             * contested value, and a reader who wants to argue with a
             * weight needs to know whose weights they are on both
             * layouts — it went missing on this one for exactly as long
             * as the contested layout had no value that could reach it.
             */ ?>
            <?php if (!empty($verdict['composition_note'])): ?>
                <p class="vp-comp-note">
                    <?= h($verdict['composition_note']) ?>
                </p>
            <?php endif; ?>

        </div>

    </div>
<?php endif; ?>
