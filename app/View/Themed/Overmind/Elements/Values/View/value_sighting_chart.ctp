<?php
/**
 * The overlay: what was reported, and what it did to the value's shelf
 * life.
 *
 * The reader can see a burst of reports lift the line, and — the harder
 * thing — see a false positive land and lift nothing. That is the whole
 * argument for this panel and it is why the curve is not in a card of
 * its own.
 *
 * **The line changed subject in phase 5** and the panel is better for
 * it (`prd/analyst-profile/06-staleness.md` §4.2). It used to be one
 * decay score per applicable model: a second opinion about *how bad is
 * this*, on a page whose ledger answers that from more evidence, drawn
 * against a count of reports. It is now the **TTL runway** — the share
 * of the value's shelf life still left — so the two axes carry two
 * different quantities rather than two estimates of one, and the
 * question they answer together is one an analyst actually has.
 *
 * One line rather than two, for the same reason: a value has one shelf
 * life however many models MISP would have scored it under.
 *
 * No threshold is drawn, and now there is none to draw. A decay model's
 * threshold was a constant chipped over the plot and repeated in the
 * readout at every column; expiry is the line reaching the axis, which
 * the axis already shows.
 *
 * All three kinds of report are stacked by organisation. Sightings
 * alone used to be, with false positives and expirations pooled into a
 * series each — so a sighting was `CIRCL saw this` and a contradiction
 * was nobody's, and the legend filed `False positive` among the
 * organisations under a heading reading `Reported by`. The rail beside
 * this has always counted a contradiction as participation; the chart
 * says the same thing now, and the readout names the reporter of every
 * count it shows.
 *
 * The two contradicting kinds hang below the axis. They used to stack
 * upwards with the sightings, which put `this report argues against the
 * value` in the colour channel — competing with six organisation hues
 * that cycle at the seventh reporter — and the busiest value on a real
 * instance has six. So the two marks the panel exists to make visible
 * were the two hardest to find. Direction cannot be crowded out: below
 * the line argues against the value, at any grain, in either theme, and
 * in greyscale. Colour is left doing what it is good at, which is
 * identity, and the collision that used to matter most is retired
 * rather than tuned — a contradiction and an organisation can no longer
 * touch.
 *
 * Both scales are therefore pinned, so one pixel row is zero on both.
 * A score is 0–100 over the band above the line and the same negative
 * share below it, where it draws nothing; otherwise a model at zero
 * would cut through the contradictions it is supposed to be read
 * against.
 *
 * Both axes are captioned in words above the chart. An overlay with two
 * scales that labels neither is a trick, and the left one is a count
 * while the right one is a score out of a hundred.
 *
 * Chart.js rather than the mockup's inline SVG (`00-shared.md` §7): the
 * artifact could not fetch a script, the page already loads one. Every
 * colour goes in as `var(--…)` and is resolved against the canvas at
 * init, so the chart follows the theme it cannot inherit — there is not
 * a hex value in this file.
 *
 * Lazily loaded from ValuesController::viewSightingChart.
 *
 * @var array $valueIntelligence
 * @var string $valueB64
 */
App::uses('ValueIntelligenceBuckets', 'Tools/ValueIntelligence');

$series = $valueIntelligence['sighting_series'];
$sightings = $valueIntelligence['sightings'];
$relevance = $valueIntelligence['relevance'];
$notes = $valueIntelligence['sighting_notes'];
$positive = $sightings['total'] - $sightings['fp'] - $sightings['expiration'];

/*
 * The three kinds of report, named once. The toggles above the chart,
 * the headings in the hover readout and the breakdown on each reporter
 * key are the same three words, so they are declared here rather than
 * three times over.
 */
$kindLabels = array(
    'sighting' => __('Sightings'),
    'fp' => __('False positives'),
    'expiration' => __('Expirations'),
);

/*
 * The three types, with the reason each one is dead when it is. A count
 * of zero is rendered disabled rather than hidden: "nobody has ever
 * filed an expiration for this value" is a fact about the value, and
 * dropping the control drops the fact with it.
 */
$toggles = array(
    array(
        'key' => 'sighting',
        'label' => $kindLabels['sighting'],
        'count' => $positive,
        'why' => __('No sighting has been reported for this value'),
    ),
    array(
        'key' => 'fp',
        'label' => $kindLabels['fp'],
        'count' => $sightings['fp'],
        'why' => __('No false positive has been reported for this value'),
    ),
    array(
        'key' => 'expiration',
        'label' => $kindLabels['expiration'],
        'count' => $sightings['expiration'],
        'why' => __('No expiration sighting has been reported for this'
            . ' value'),
    ),
);

$controls = '';
foreach ($toggles as $toggle) {
    $dead = $toggle['count'] === 0;
    $controls .= '<button type="button" class="vp-sight-toggle"'
        . ' data-vp-sight-type="' . h($toggle['key']) . '"'
        . ' aria-pressed="' . ($dead ? 'false' : 'true') . '"'
        . ($dead ? ' disabled title="' . h($toggle['why']) . '"' : '')
        . '><span class="vp-sight-toggle-swatch'
        . ' vp-sight-swatch-' . h($toggle['key']) . '"></span>'
        . h($toggle['label'])
        . '<span class="vp-sight-toggle-count">'
        . h($toggle['count']) . '</span></button>';
}

/*
 * The presets that used to be three precomputed ranges. They set the
 * span; the zoom's buttons under the navigator refine it, and the
 * grain follows from whatever span results. So this control keeps its
 * labels and stops being the only way to change what the chart shows.
 */
if ($series !== null && count($series['spans']) > 1) {
    $controls .= '<select class="form-select form-select-sm'
        . ' vp-sight-range" data-vp-sight-range'
        . ' aria-label="' . h(__('Time range')) . '">';
    foreach ($series['spans'] as $span) {
        $controls .= '<option value="' . h($span['key']) . '"'
            . ($span['key'] === $series['default_span']
                ? ' selected'
                : '')
            . '>' . h($span['label']) . '</option>';
    }
    // Selected by the script once the zoom leaves every preset.
    $controls .= '<option value="" disabled hidden'
        . ' data-vp-sight-range-custom>' . h(__('Custom span'))
        . '</option>';
    $controls .= '</select>';
}

$subtitle = $sightings['total'] === 0
    ? h(__('Never sighted'))
    : h(sprintf(
        __('%1$s · %2$s, %3$s, %4$s · last one %5$s'),
        __n(
            '%s report',
            '%s reports',
            $sightings['total'],
            $sightings['total']
        ),
        __n('%s sighting', '%s sightings', $positive, $positive),
        __n(
            '%s false positive',
            '%s false positives',
            $sightings['fp'],
            $sightings['fp']
        ),
        __n(
            '%s expiration',
            '%s expirations',
            $sightings['expiration'],
            $sightings['expiration']
        ),
        $sightings['last']
    ));

/*
 * The whole span at every grain the rule permits, plus one count per
 * day per series. The transpose that used to happen here is gone with
 * the three precomputed ranges it transposed: the browser sums a slice
 * of these per drawn bar, so a zoom step and a preset switch are the
 * same arithmetic rather than a re-fetch or a re-derive (§13.1).
 *
 * The runway is one sample a day rather than one a bucket, and the
 * browser reads the sample at each bar's last day. A count sums when
 * bars are merged; a share of remaining shelf life does not.
 */
$payload = null;
if ($series !== null) {
    $payload = array(
        'orgs' => $series['orgs'],
        'plan' => $series['plan'],
        'daily' => $series['daily'],
        'curves' => $series['curves'],
        'spans' => $series['spans'],
        'default' => $series['default_span'],
        'labels' => array(
            /*
             * The readout's headings. One per kind of report and one
             * for the scores, because it groups by what a row is: the
             * rows under a kind are counts on the left axis and belong
             * to the organisation named in each, and the rows under the
             * last are scores on the right. A flat list of all of them
             * was the tab's least readable thing, and it was also where
             * a false positive had no reporter to name.
             */
            'kinds' => $kindLabels,
            /*
             * The same three words counted, for the breakdown on a
             * reporter key — `1 Expirations` is what a heading label
             * reads like in a sentence. Both forms go over the wire
             * because the choice is made in the browser, against a
             * number the browser is the first to know: the split is per
             * selected range.
             */
            'kindCounted' => array(
                'sighting' => array(__('sighting'), __('sightings')),
                'fp' => array(
                    __('false positive'),
                    __('false positives'),
                ),
                'expiration' => array(
                    __('expiration'),
                    __('expirations'),
                ),
            ),
            'score' => __('Lifetime'),
            /*
             * The axis now has two halves and the caption is the only
             * place that says which is which before the reader hovers
             * anything. `up` and `down` rather than `positive` and
             * `negative`: the numbers on the axis are counts either
             * way, and the sign is a direction rather than a quantity.
             */
            'perUnit' => array(
                'day' => __(
                    'Reports per day, stacked by organisation'
                    . ' · sightings up, contradictions down'
                ),
                'week' => __(
                    'Reports per week, stacked by organisation'
                    . ' · sightings up, contradictions down'
                ),
                'month' => __(
                    'Reports per month, stacked by organisation'
                    . ' · sightings up, contradictions down'
                ),
            ),
            'perColumn' => ValueIntelligenceBuckets::columnLabels(),
        ),
    );
}
?>
<div class="card shadow-sm mb-3 vp-panel"
     style="--vp-panel-color: var(--sighting);"
     <?= $payload === null ? '' : 'data-vp-sight' ?>>

    <?= $this->element('Values/View/value_panel_header', array(
        'panelTitle' => __('Sightings over time'),
        'panelIcon' => 'misp-icon misp-icon-sighting misp-simple',
        'panelColor' => 'var(--sighting)',
        'panelSub' => $subtitle,
        'panelExtra' => $series === null ? null : $controls,
    )) ?>

    <?php if ($series === null): ?>

        <?php
        /*
         * No attribute, so no axis. A chart drawn over the last 90 days
         * for a value that has never existed would be inventing the
         * window as well as the emptiness.
         */
        ?>
        <div class="p-3">
            <div class="vp-empty">
                <span class="misp-icon misp-icon-sighting misp-simple"></span>
                <span><?= __('Nobody has reported seeing this.') ?></span>
            </div>
        </div>

    <?php else: ?>

        <div class="p-3">

            <div class="vp-sight-axes">
                <span class="vp-subhead" data-vp-sight-axis-left>
                    <?= __('Reports per day, stacked by organisation'
                        . ' · sightings up, contradictions down') ?>
                </span>
                <span class="vp-subhead vp-sight-axis-right">
                    <?= __('Lifetime left · % of the full lifetime') ?>
                </span>
            </div>

            <div class="vp-chart vp-sight-main">
                <canvas id="vp-sight-main" role="img"
                        aria-label="<?= h(__(
                            'Reports per organisation over time — sightings'
                            . ' above the axis, false positives and'
                            . ' expirations below it — with the share of'
                            . ' the value\'s lifetime still left'
                            . ' overlaid'
                        )) ?>"></canvas>
                <?php if ($sightings['total'] === 0): ?>
                    <?php
                    /*
                     * The axes stay. "No sightings" and "no shelf life"
                     * are different claims, and the rail beside this
                     * still carries a runway — a value nobody has
                     * reported still ages, from its own encoding date.
                     */
                    ?>
                    <div class="vp-sight-overlay">
                        <?= __('Nobody has reported seeing this.') ?>
                    </div>
                <?php endif; ?>
            </div>

            <div class="vp-sight-nav" data-vp-sight-nav>
                <canvas id="vp-sight-nav" role="img"
                        aria-label="<?= h(__(
                            'All sightings in the selected range, as a'
                            . ' navigator'
                        )) ?>"></canvas>
                <?= $this->element('genericElementsBS5/brush') ?>
            </div>

            <div class="vp-sight-nav-caption">
                <span>
                    <?= __('Drag the rail to change the range — the table'
                        . ' below follows it') ?>
                </span>
                <span class="vp-sight-nav-window" data-vp-sight-window>
                    <?= h($series['spans'][0]['from']) ?>
                    →
                    <?= h($series['today']) ?>
                </span>
            </div>

            <?php
            /*
             * Under the navigator rather than over it, because the
             * navigator is what it moves. Full width here, so the
             * caption sits beside the buttons instead of above them.
             */
            ?>
            <div class="vp-sight-zoom">
                <?= $this->element('Values/View/value_zoom', array(
                    'zoomLabel' => __('Zoom the navigator'),
                    'zoomAway' => __('the range is not in view'),
                    'zoomSelection' => __('Look inside the range'),
                    'grain' => ValueIntelligenceBuckets::columnLabels(),
                )) ?>
            </div>

            <?php
            /*
             * Three groups, each behind its own heading and separated
             * by a rule, matching the readout: who reported, which of
             * those reports argue against the value, and what the
             * the shelf life is. One run of keys made the overlay
             * look like a seventh reporter — and it filed `False
             * positive` among the organisations, as though a
             * contradiction were somebody's name.
             *
             * The reporter keys are buttons. A stack of a dozen
             * organisations is unreadable at the bar it matters in, and
             * the only control the tab offered was three type toggles
             * that cannot say `just this org` — so the legend, which is
             * already the list of organisations and already sits under
             * the chart, becomes the filter. Switching one off now
             * takes its false positives and expirations with it, since
             * those are its reports too. The type toggles above stay
             * what they are: they choose which of the three kinds are
             * drawn at all.
             *
             * A never-sighted value keeps its axes and its curve, so it
             * reaches here with no reporter at all. Each heading goes
             * with its group: a label looking for a list is worse than
             * no label.
             */
            ?>
            <div class="vp-sight-legend" data-vp-sight-legend>
                <?php if (!empty($series['orgs'])): ?>
                    <div class="vp-sight-legend-group">
                        <span class="vp-sight-legend-head">
                            <?= __('Reported by') ?>
                        </span>
                        <?php foreach ($series['orgs'] as $i => $org): ?>
                            <button type="button" class="vp-sight-key
                                    vp-sight-key-org"
                                    data-vp-sight-key-org="<?= (int)$i ?>"
                                    aria-pressed="true">
                                <span class="vp-sight-swatch"
                                      style="--vp-sight-hue:
                                          var(--vp-sight-org-<?=
                                          (int)($i % 6) + 1 ?>);"></span>
                                <?= h($org) ?>
                                <b data-vp-sight-key-count></b>
                            </button>
                        <?php endforeach; ?>
                    </div>
                <?php endif; ?>
                <?php if ($sightings['fp'] > 0
                    || $sightings['expiration'] > 0
                ): ?>
                    <?php
                    /*
                     * These two are not reporters and no longer sit
                     * among them. Their job here is to decode the two
                     * colours in the stack that are not an
                     * organisation's: a contradiction keeps its own
                     * colour whoever filed it, and the reporter is a
                     * row in the readout.
                     *
                     * The hue goes in the same variable the reporter
                     * keys use rather than through the `-fp` class the
                     * toggles carry. `.vp-sight-swatch` is declared
                     * after those classes and paints from
                     * `--vp-sight-hue`, so a legend swatch keyed by
                     * class alone came out transparent — these two
                     * have been invisible since the legend was
                     * written.
                     */
                    ?>
                    <div class="vp-sight-legend-group">
                        <span class="vp-sight-legend-head">
                            <?= __('Below the line') ?>
                        </span>
                        <?php if ($sightings['fp'] > 0): ?>
                            <span class="vp-sight-key">
                                <span class="vp-sight-swatch"
                                      style="--vp-sight-hue:
                                          var(--vp-sight-fp);"></span>
                                <?= __('False positive') ?>
                                <b data-vp-sight-key-fp></b>
                            </span>
                        <?php endif; ?>
                        <?php if ($sightings['expiration'] > 0): ?>
                            <span class="vp-sight-key">
                                <span class="vp-sight-swatch"
                                      style="--vp-sight-hue:
                                          var(--vp-sight-exp);"></span>
                                <?= __('Expiration') ?>
                                <b data-vp-sight-key-exp></b>
                            </span>
                        <?php endif; ?>
                    </div>
                <?php endif; ?>
                <?php if ($relevance['state'] !== null): ?>
                    <div class="vp-sight-legend-group">
                        <span class="vp-sight-legend-head">
                            <?= __('Lifetime') ?>
                        </span>
                        <span class="vp-sight-key">
                            <span class="vp-sight-swatch
                                         vp-sight-swatch-line"
                                  style="--vp-sight-hue:
                                      var(--vp-sight-curve-1);"></span>
                            <?= h(sprintf(
                                __('%s days of TTL'),
                                $relevance['ttl']['days']
                            )) ?>
                            <b><?= h(sprintf(
                                '%d%%',
                                (int)round($relevance['runway'] * 100)
                            )) ?></b>
                        </span>
                    </div>
                <?php endif; ?>
            </div>

            <?php
            /*
             * Two counts with two scopes are on screen at once, which
             * is one fewer than before this phase: a reporter key and
             * the Reporters card now count the same thing — every
             * report of any kind — and differ only in that one is the
             * selected range and the other the whole value. The
             * toggles are the third scope and always were.
             *
             * What still needs saying is the one place the count and
             * the colour part company. A reporter's number includes
             * its contradictions; its swatch does not, because those
             * are drawn under the line in the red and the orange.
             */
            ?>
            <p class="vp-sight-legend-note">
                <?php if (!empty($series['orgs'])): ?>
                    <?= h(__(
                        'Click an organisation to take it out of the'
                        . ' chart, contradictions included; its count'
                        . ' stays, and the table below is not filtered'
                        . ' by it.'
                    )) ?>
                    <?= h(__(
                        'A reporter\'s count is every report it filed in'
                        . ' the selected range, of any kind — hover a key'
                        . ' for the split. Its contradictions hang below'
                        . ' the line in their own colour rather than the'
                        . ' reporter\'s, and the axis counts up in both'
                        . ' directions.'
                    )) ?>
                <?php endif; ?>
                <?= h(__(
                    'The toggles above count the whole value rather than'
                    . ' the range.'
                )) ?>
            </p>

            <?php
            /*
             * The sentence the whole overlay exists to earn. A curve in
             * a card of its own could assert it; only a curve drawn
             * through the bars can show it.
             */
            ?>
            <p class="vp-sight-note">
                <i class="fas fa-circle-info"></i>
                <span><?= h($notes['fp_moves_nothing']) ?></span>
            </p>

            <?php if (!empty($series['clipped'])): ?>
                <?php
                /*
                 * A cap, not a permission — §14.6 keeps cap notices for
                 * exactly this reason. `All time` on a value first seen
                 * in 2015 would be 3,948 daily samples, so the span is
                 * bounded and the label says which question it is
                 * answering.
                 */
                ?>
                <p class="vp-sight-note">
                    <i class="fas fa-scissors"></i>
                    <span><?= h(sprintf(
                        __('Charted from %1$s. This value was first'
                            . ' recorded on %2$s; the chart bounds its'
                            . ' span so the runway stays one sample a'
                            . ' day.'),
                        $series['from'],
                        $series['first']
                    )) ?></span>
                </p>
            <?php endif; ?>

        </div>

        <script type="application/json" data-vp-sight-data>
            <?= json_encode($payload) ?>
        </script>

    <?php endif; ?>

</div>
