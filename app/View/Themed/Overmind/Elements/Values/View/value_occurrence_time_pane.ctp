<?php
/**
 * One date control on the occurrence rail: a brushable strip of
 * calendar buckets over two date inputs, and a caption.
 *
 * @var string $key The range name rows carry in `data-vp-times`
 * @var string $label
 * @var array|null $span `from`, `to`
 * @var array|null $histogram `unit`, `max`, `bars`
 * @var string $absent What to say when no row carries this date
 * @var string|null $note
 * @var bool $countRows Rows carry intervals, so the hover count is of
 *     rows overlapping the window rather than a sum of bars
 */
App::uses('ValueStatsTool', 'Tools/ValueIntelligence');

$note = $note ?? null;
/*
 * The same words `value_zoom` uses for a grain, so the two
 * captions on this page name a bucket the same way.
 */
$grainWords = array(
    'day' => __('one bar a day'),
    'week' => __('one bar a week'),
    'month' => __('one bar a month'),
);
?>
<?php if ($span === null): ?>
    <?php
    /*
     * No row carries this date, so there is nothing
     * to bound. A live-looking control over a column
     * that is empty for every row is the one thing
     * this page's rules rule out.
     */
    ?>
    <div class="small text-muted">
        <?= h($absent) ?>
    </div>
<?php else: ?>
    <?php
    $caption = $histogram === null
        ? sprintf(
            __('%1$s to %2$s'),
            $span['from'],
            $span['to']
        )
        : sprintf(
            __('%1$s · %2$s to %3$s'),
            $grainWords[$histogram['unit']],
            $span['from'],
            $span['to']
        );
    ?>
    <?php if ($histogram !== null): ?>
        <?php
        /*
         * The same brush the History chart and the Sightings
         * navigator use, over a strip of CSS bars rather than a
         * canvas: it needs to be a third the height of History's
         * chart to sit in a `col-lg-3` rail.
         *
         * Drag to pick a range, click to clear. The gesture writes
         * the two date inputs below, so the window stays statable as
         * two dates and one filter path runs whether the reader
         * brushed or typed.
         */
        ?>
        <div class="vp-timebrush"
             data-vp-timebrush="<?=
                 h($key) ?>"<?= empty($countRows) ? '' :
                 ' data-vp-timebrush-count="rows"' ?>>
            <div class="vp-spark vp-spark-attribute
                        vp-spark-flush"
                 role="img"
                 aria-label="<?= h(sprintf(
                     __(
                         'Occurrences by %1$s, %2$s.'
                         . ' Drag to pick a range.'
                     ),
                     mb_strtolower($label),
                     $grainWords[$histogram['unit']]
                 )) ?>">
                <?php foreach (
                    $histogram['bars'] as $bar
                ): ?>
                    <span class="vp-spark-bar<?=
                        $bar['count'] === 0
                            ? ' vp-spark-bar-empty'
                            : '' ?>"
                          style="--vp-spark-h: <?=
                              h($histogram['max'] > 0
                                  ? round(
                                      $bar['count']
                                      / $histogram['max']
                                      * 100
                                  )
                                  : 0) ?>%"
                          data-vp-bucket-from="<?=
                              h($bar['from']) ?>"
                          data-vp-bucket-to="<?=
                              h($bar['to']) ?>"
                          data-vp-bucket-label="<?=
                              h($bar['label']) ?>"
                          data-vp-bucket-count="<?=
                              h($bar['count']) ?>">
                    </span>
                <?php endforeach; ?>
            </div>
            <?= $this->element('genericElementsBS5/brush') ?>
        </div>
        <?php $scale = ValueStatsTool::timeScale($histogram); ?>
        <?php if (!empty($scale)): ?>
            <?php
            /*
             * `aria-hidden`: the strip's own
             * accessible name says what the axis
             * is and the caption below states both
             * ends, so a screen reader walking
             * fifty-two bare slots between them is
             * reading the gridlines rather than
             * the chart.
             *
             * Outside `.vp-timebrush` rather than
             * in it: the brush layer covers that
             * box edge to edge, and an axis under
             * it would be both dimmed by the mask
             * and unreadable through the window.
             */
            ?>
            <div class="vp-spark-scale
                        vp-timebrush-scale"
                 aria-hidden="true">
                <?php foreach (
                    $histogram['bars'] as $at => $bar
                ): ?>
                    <span class="vp-spark-slot<?=
                        array_key_exists($at, $scale)
                            ? ' vp-spark-slot-tick'
                            : '' ?>"><?php
                        if (!empty($scale[$at])):
                    ?><span class="vp-spark-tick"><?=
                        h($scale[$at])
                    ?></span><?php endif; ?></span>
                <?php endforeach; ?>
            </div>
        <?php endif; ?>
    <?php endif; ?>

    <div class="input-group input-group-sm">
        <input type="date" class="form-control"
               data-vp-range-from="<?=
                   h($key) ?>"
               min="<?= h($span['from']) ?>"
               max="<?= h($span['to']) ?>"
               aria-label="<?= h(sprintf(
                   __('%s from'),
                   $label
               )) ?>">
        <span class="input-group-text">
            <?= __('to') ?>
        </span>
        <input type="date" class="form-control"
               data-vp-range-to="<?=
                   h($key) ?>"
               min="<?= h($span['from']) ?>"
               max="<?= h($span['to']) ?>"
               aria-label="<?= h(sprintf(
                   __('%s to'),
                   $label
               )) ?>">
    </div>
    <?php
    /*
     * States the grain, and names the bucket under
     * the pointer while the reader is over the
     * strip. A bar three pixels wide is not
     * self-describing, and the brush layer sits on
     * top of the bars so their own `title` never
     * reaches the reader.
     */
    ?>
    <div class="small text-muted mt-1"
         data-vp-timebrush-caption="<?=
             h($key) ?>"
         data-vp-caption-default="<?= h($caption) ?>">
        <?= h($caption) ?>
    </div>
    <?php if ($note !== null): ?>
        <div class="small text-muted mt-1">
            <?= h($note) ?>
        </div>
    <?php endif; ?>
<?php endif; ?>
