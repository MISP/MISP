<?php
/**
 * Who put this value on the instance, and when.
 *
 * Two summaries side by side, neither of them new to the page and both
 * new to this tab:
 *
 *   - **When** — a bar a month over the value's whole life, which is
 *     the Timeline tab's *Activity on this value* with the axis set by
 *     the data's extent rather than by a brush. The silent months are
 *     drawn, because the run is the reading.
 *   - **Who** — occurrences per organisation with each one's `to_ids`
 *     stance, which is the occurrence half of the Assessment tab's
 *     *Who says what*. Same read, same stance word.
 *
 * Both replace hand-counting: a reader tallied the *Reported by* column
 * of the occurrence preview above to get the first and squinted at
 * *Last seen* for the second, over a capped sample that could not
 * support either. Phase 31.
 *
 * Lazily loaded into `.ajax-card` from ValuesController::viewReporting.
 *
 * @var array $valueIntelligence
 * @var string $valueB64
 */
$reporting = $valueIntelligence['reporting'];
$months = $reporting['months'];
$orgs = $reporting['orgs'];
$peak = empty($months) ? 0 : max($months);
$topOrg = empty($orgs) ? 0 : $orgs[0]['occurrences'];
$hidden = $reporting['orgs_total'] - count($orgs);

/*
 * The months with something in them, out of the months in the span —
 * the same fraction `lifecycle.continuity` scores and the Assessment
 * tab prints in words. Stated here as the subtitle because it is what
 * the strip beneath it is *for*: a value reported in 16 of 51 months
 * and one reported in 16 consecutive months draw very differently and
 * hold the same occurrence count.
 */
$active = 0;
foreach ($months as $count) {
    if ($count > 0) {
        $active++;
    }
}

/*
 * Both halves' denominators, in the header, because both are read as
 * *out of what* and neither belongs under the thing it divides. The
 * second is the split's own sum and not the fact strip's total —
 * `forReporting` has the argument — so the word `live` is doing work:
 * a soft-deleted occurrence is in the strip's 26 and not in this 26.
 */
$clauses = array();
if (!empty($months)) {
    $clauses[] = sprintf(
        __n(
            'Reported in %1$s of %2$s month',
            'Reported in %1$s of %2$s months',
            count($months)
        ),
        number_format($active),
        number_format(count($months))
    );
}
if (!empty($orgs)) {
    $clauses[] = sprintf(
        __n(
            '%1$s live occurrence from %2$s',
            '%1$s live occurrences from %2$s',
            $reporting['occurrences']
        ),
        number_format($reporting['occurrences']),
        sprintf(
            __n(
                '%s organisation',
                '%s organisations',
                $reporting['orgs_total']
            ),
            number_format($reporting['orgs_total'])
        )
    );
}
$subtitle = empty($clauses)
    ? h(__('Nothing dated to report'))
    : implode(' &nbsp;·&nbsp; ', array_map('h', $clauses));

/*
 * ------------------------------------------------------------------
 * The strip's scale
 * ------------------------------------------------------------------
 * **A tick at every January**, which is the only gridline a strip of
 * months has that is not arbitrary. The strip carried its first and
 * last month and nothing between, so a bar four fifths of the way along
 * a nine-year span could be read as *recent* and no more precisely than
 * that.
 *
 * **The scale is a row of the bars' own geometry, not a set of
 * percentages.** `.vp-spark-bar` is `flex: 1 1 0` with a `max-width`,
 * so on a short span the bars stop growing and bunch at the left — and
 * a tick placed at `i / n` of the width would then sit nowhere near the
 * bar it names. One empty slot per month, sharing the bars' flex rules,
 * puts every tick on its own bar whatever the cap does.
 *
 * **Thinned rather than crowded.** `0.0.0.0` spans 128 months, which is
 * eleven Januaries over ~560px; every year labelled would be four-digit
 * labels ~50px apart. The marks stay annual — the gridline is the
 * point — and one label in `$tickStep` carries the year.
 *
 * A tick in the last two months of the span draws its mark and keeps
 * its label, which would otherwise hang off the right edge of the card.
 */
$tickYears = array();
$monthKeys = array_keys($months);
foreach ($monthKeys as $index => $month) {
    if (substr($month, -2) === '01') {
        $tickYears[] = $index;
    }
}
$tickStep = max(1, (int)ceil(count($tickYears) / 7));
$tickLabels = array();
foreach ($tickYears as $nth => $index) {
    $tickLabels[$index] = ($nth % $tickStep === 0
        && $index < count($monthKeys) - 2)
        ? substr($monthKeys[$index], 0, 4)
        : null;
}

/*
 * **The chip wears MISP's IDS shield, and MISP's IDS colours with it.**
 *
 * The glyph is `fa-shield-halved`, which is what
 * `Fields/ids` draws in the occurrence table two cards above this one —
 * so the chip says *which flag* it is a reading of rather than leaving
 * the reader to infer it from the word alone.
 *
 * That forced the palette. `yes` was drawn in the attribute green until
 * the shield arrived, and a green shield here beside an **amber** one
 * up there is one fact in two colours on one tab. Amber is *IDS
 * active*, grey is *IDS inactive*, and this card now says the same
 * thing in the same colours as the table it summarises.
 *
 * `mixed` keeps amber and takes a **dashed** edge rather than a third
 * hue — the rule the relevance chip already follows, direction in the
 * geometry. An organisation with the value twice, actionable once, has
 * not made half a decision; it has made none, and a shade between two
 * colours would say it made half.
 *
 * `none` is unreachable and is kept as a guard: `orgStanceFor` counts
 * every one of an organisation's non-deleted rows into `to_ids_yes` or
 * `to_ids_no`, and a row exists for that organisation or it would not
 * be in the result at all.
 */
$stanceTone = array(
    __('yes') => 'vp-stance-yes',
    __('no') => 'vp-stance-no',
    __('mixed') => 'vp-stance-mixed',
    __('none') => 'vp-stance-none',
);

$stanceTitle = array(
    __('yes') => __('Every occurrence from this organisation is'
        . ' flagged to_ids'),
    __('no') => __('No occurrence from this organisation is flagged'
        . ' to_ids'),
    __('mixed') => __('This organisation flags some of its occurrences'
        . ' to_ids and not others'),
    __('none') => __('This organisation states no to_ids flag'),
);
?>
<div class="card shadow-sm mb-3 vp-panel"
     style="--vp-panel-color: var(--object);">

    <?= $this->element('Values/View/value_panel_header', array(
        'panelTitle' => __('Reporting'),
        'panelIcon' => 'misp-icon misp-icon-organisation misp-simple',
        'panelColor' => 'var(--object)',
        'panelSub' => $subtitle,
    )) ?>

    <?php if (empty($orgs) && empty($months)): ?>
        <?php
        /*
         * The same distinction the occurrence card draws, for the same
         * reason: absent and hidden are different answers and only one
         * of them is knowable from here.
         */
        ?>
        <div class="vp-empty">
            <span class="misp-icon misp-icon-organisation misp-simple"></span>
            <span><?= __('No event you can see carries this value.') ?></span>
        </div>
    <?php else: ?>
        <div class="p-3 vp-reporting">

            <div class="vp-reporting-when">
                <div class="vp-subhead"><?= __('Reported in') ?></div>
                <?php if (empty($months)): ?>
                    <div class="vp-empty vp-empty-inline">
                        <i class="fas fa-clock"></i>
                        <span><?= __('No occurrence carries a date.') ?></span>
                    </div>
                <?php else: ?>
                    <div class="vp-spark" role="img"
                         aria-label="<?= h(__(
                             'Occurrences by month, oldest first'
                         )) ?>">
                        <?php foreach ($months as $month => $count): ?>
                            <span class="vp-spark-bar<?= $count === 0
                                ? ' vp-spark-bar-empty'
                                : '' ?>"
                                  style="--vp-spark-h: <?=
                                      $peak > 0
                                          ? round(100 * $count / $peak)
                                          : 0 ?>%;"
                                  title="<?= h(sprintf(
                                      __n(
                                          '%2$s — %1$s occurrence',
                                          '%2$s — %1$s occurrences',
                                          $count
                                      ),
                                      number_format($count),
                                      $month
                                  )) ?>"></span>
                        <?php endforeach; ?>
                    </div>
                    <?php if (!empty($tickYears)): ?>
                        <?php
                        /*
                         * `aria-hidden`: the strip's accessible name
                         * already says what the axis is, and a screen
                         * reader walking eleven bare years between it
                         * and the ends below is reading the gridlines
                         * rather than the chart.
                         */
                        ?>
                        <div class="vp-spark-scale" aria-hidden="true">
                            <?php foreach ($monthKeys as $index => $month): ?>
                                <span class="vp-spark-slot<?=
                                    isset($tickLabels[$index])
                                        ? ' vp-spark-slot-tick'
                                        : '' ?>"><?php
                                    if (!empty($tickLabels[$index])): ?>
                                    <span class="vp-spark-tick"><?=
                                        h($tickLabels[$index])
                                    ?></span>
                                <?php endif; ?></span>
                            <?php endforeach; ?>
                        </div>
                    <?php endif; ?>
                    <?php
                    /*
                     * The exact ends, which the year ticks above round
                     * off — and one label where the span is one month,
                     * because `2017-01 … 2017-01` is a range that does
                     * not range.
                     */
                    ?>
                    <div class="vp-spark-axis">
                        <span><?= h(array_key_first($months)) ?></span>
                        <?php if (count($months) > 1): ?>
                            <span><?= h(array_key_last($months)) ?></span>
                        <?php endif; ?>
                    </div>
                <?php endif; ?>
            </div>

            <div class="vp-reporting-who">
                <div class="vp-subhead">
                    <?= __('Occurrences by organisation') ?>
                </div>
                <?php if (empty($orgs)): ?>
                    <div class="vp-empty vp-empty-inline">
                        <span class="misp-icon misp-icon-organisation
                                     misp-simple"></span>
                        <span><?= __(
                            'Every occurrence is soft-deleted.'
                        ) ?></span>
                    </div>
                <?php else: ?>
                    <?php foreach ($orgs as $org): ?>
                        <div class="vp-reporter">
                            <span class="vp-reporter-name">
                                <?= h($org['name']) ?>
                            </span>
                            <span class="vp-stance <?= h(
                                $stanceTone[$org['stance']] ?? ''
                            ) ?>" title="<?= h(
                                $stanceTitle[$org['stance']]
                                    ?? $org['stance']
                            ) ?>">
                                <i class="fas fa-shield-halved"></i>
                                <span><?= h($org['stance']) ?></span>
                            </span>
                            <span class="vp-reporter-track">
                                <span class="vp-reporter-fill" style="width: <?=
                                    $topOrg > 0
                                        ? round(100 * $org['occurrences']
                                            / $topOrg)
                                        : 0 ?>%;"></span>
                            </span>
                            <span class="vp-reporter-count">
                                <?= h(number_format($org['occurrences'])) ?>
                            </span>
                        </div>
                    <?php endforeach; ?>

                    <?php
                    /*
                     * The cap is the drawing's and not the read's, so
                     * what it hides is a count this card holds rather
                     * than a number it would have to ask for.
                     */
                    ?>
                    <?php if ($hidden > 0): ?>
                        <div class="vp-reporting-rest">
                            <?= h(sprintf(
                                __n(
                                    '%s further organisation not shown',
                                    '%s further organisations not shown',
                                    $hidden
                                ),
                                number_format($hidden)
                            )) ?>
                        </div>
                    <?php endif; ?>

                <?php endif; ?>
            </div>

        </div>
    <?php endif; ?>

</div>
