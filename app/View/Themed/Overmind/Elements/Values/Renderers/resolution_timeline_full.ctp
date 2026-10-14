<?php
/**
 * Every resolution, with its window and how often it was seen.
 *
 * Sorted by how recently each was current, because *what does this
 * resolve to now* is the question and *what did it resolve to in 2014*
 * is the context. The observation count is drawn as a number rather
 * than as a bar: it spans four orders of magnitude on a single value
 * and a bar chart of it is one bar and a row of slivers.
 *
 * A dated answer gets a month strip over the table that filters it:
 * drag to keep the resolutions current in a period, click to clear.
 * It is the Occurrences rail's brush, fed through the same list
 * engine, and a row matches when its window overlaps the period.
 *
 * @var array $data
 */
$periods = $data['periods'] ?? array();
$peak = empty($periods) ? 0 : max(array_column($periods, 'count'));
$drawn = $data['dated'] && $peak > 0 && count($periods) > 1;
// The brush runs on the value page's list engine; elsewhere the strip is
// only read.
$brushed = $drawn && empty($this->viewVars['vpEventScope']);
$stamp = function ($row) {
    $first = $row['first'] ?? $row['last'];
    $last = $row['last'] ?? $row['first'];
    if ($first === null) {
        return null;
    }
    return 'seen:' . date('YmdHi', $first) . '-' . date('YmdHi', $last);
};
$monthName = function ($month) {
    return date('M Y', strtotime($month . '-01'));
};
// What one bar says, on hover.
$tip = function ($period) use ($monthName) {
    return sprintf(__n(
        '%2$s · %1$s resolution current',
        '%2$s · %1$s resolutions current',
        $period['count']
    ), number_format($period['count']), $monthName($period['label']));
};
// Too many bars for a gap between each.
$dense = count($periods) > 48;
$key = '';
if ($drawn) {
    $peakAt = $periods[0];
    foreach ($periods as $period) {
        if ($period['count'] > $peakAt['count']) {
            $peakAt = $period;
        }
    }
    $key = h(__('Resolutions current each month')) . ' · ' . sprintf(
        h(__('peak %1$s in %2$s')),
        '<b>' . h(number_format($peakAt['count'])) . '</b>',
        h($monthName($peakAt['label']))
    );
}
?>
<div class="vp-rf vp-rf-res"<?= $brushed ? ' data-vp-list' : '' ?>>
    <?php if (!$data['dated']): ?>
        <p class="vp-rf-note"><?= h(
            __('These are current resolutions. The source that'
                . ' returned them carries no first or last seen, so'
                . ' there is no history to draw.')
        ) ?></p>
    <?php elseif ($data['first'] !== null): ?>
        <p class="vp-rf-note"><?= h(sprintf(
            __('%1$s resolutions, first seen %2$s, last %3$s.'),
            number_format($data['distinct']),
            date('Y-m-d', $data['first']),
            $data['last'] === null
                ? '?' : date('Y-m-d', $data['last'])
        )) ?></p>
    <?php endif; ?>

    <?php if ($brushed): ?>
        <?php $span = reset($periods)['label'] . ' – '
            . end($periods)['label']; ?>
        <div class="vp-rf-res-brush">
            <div class="vp-rf-res-key"><?= $key ?> · <?= h(__(
                'drag across the bars to filter the table'
            )) ?></div>
            <div class="vp-timebrush" data-vp-timebrush="seen"
                 data-vp-timebrush-count="rows">
                <div class="vp-spark vp-spark-flush vp-rf-res-spark<?=
                    $dense ? ' is-dense' : '' ?>"
                     role="img" aria-label="<?= h(__(
                         'Resolutions current per month, oldest first.'
                         . ' Drag to pick a period.'
                     )) ?>">
                    <?php foreach ($periods as $period): ?>
                        <span class="vp-spark-bar<?= $period['count'] === 0
                            ? ' vp-spark-bar-empty' : '' ?>"
                              style="--vp-spark-h: <?= h(round(
                                  100 * $period['count'] / $peak
                              )) ?>%"
                              data-vp-bucket-from="<?=
                                  h($period['from']) ?>"
                              data-vp-bucket-to="<?= h($period['to']) ?>"
                              data-vp-bucket-label="<?=
                                  h($period['label']) ?>"
                              data-vp-bucket-count="<?=
                                  h($period['count']) ?>"
                              data-vp-tip="<?= h($tip($period)) ?>"></span>
                    <?php endforeach; ?>
                </div>
                <?= $this->element('genericElementsBS5/brush') ?>
            </div>
            <?= $this->element('Values/Renderers/month_axis', array(
                'months' => array_column($periods, 'label'),
            )) ?>
            <div class="vp-rf-sub vp-rf-res-foot"
                 data-vp-facet-summary>
                <span data-vp-timebrush-caption="seen"
                      data-vp-caption-default="<?= h($span) ?>"><?=
                    h($span) ?></span>
                <span class="vp-rf-res-shown"><?= sprintf(
                    h(__('%1$s of %2$s shown')),
                    '<span data-vp-list-shown>'
                        . h(number_format($data['distinct'])) . '</span>',
                    h(number_format($data['distinct']))
                ) ?></span>
                <button type="button" class="btn btn-link vp-rf-link
                               vp-rf-res-all"
                        data-vp-facet-clear disabled><?=
                    h(__('Show all')) ?></button>
            </div>
            <input type="hidden" data-vp-range-from="seen" value="">
            <input type="hidden" data-vp-range-to="seen" value="">
        </div>
        <p class="vp-rf-note d-none" data-vp-list-empty><?= h(__(
            'No resolution was current in that period.'
        )) ?></p>
    <?php elseif ($drawn): ?>
        <div class="vp-rf-res-key"><?= $key ?></div>
        <div class="vp-rw-months<?= $dense ? ' is-dense' : '' ?>"
             role="img" aria-label="<?= h(__(
            'Resolutions current per month, oldest first.'
        )) ?>">
            <?php foreach ($periods as $period): ?>
                <span class="vp-rw-month<?= $period['count'] === 0
                    ? ' vp-rw-month-empty' : '' ?>"
                      style="--vp-rw-month-h: <?= h(round(
                          100 * $period['count'] / $peak
                      )) ?>%"
                      title="<?= h($tip($period)) ?>"></span>
            <?php endforeach; ?>
        </div>
        <?= $this->element('Values/Renderers/month_axis', array(
            'months' => array_column($periods, 'label'),
        )) ?>
        <div class="vp-rf-sub vp-rf-res-foot"><?= h(
            reset($periods)['label'] . ' – ' . end($periods)['label']
        ) ?></div>
    <?php endif; ?>

    <table class="table table-sm vp-rf-table"<?= $brushed
        ? ' data-vp-list-rows' : '' ?>>
        <thead>
            <tr>
                <th scope="col"><?= h(__('Name')) ?></th>
                <th scope="col"><?= h(__('Type')) ?></th>
                <th scope="col"><?= h(__('Resolves to')) ?></th>
                <th scope="col"><?= h(__('First')) ?></th>
                <th scope="col"><?= h(__('Last')) ?></th>
                <th scope="col" class="text-end"><?=
                    h(__('Seen')) ?></th>
                <th scope="col"><?= h(__('Source')) ?></th>
            </tr>
        </thead>
        <tbody>
            <?php foreach ($data['resolutions'] as $row): ?>
                <?php $times = $brushed ? $stamp($row) : null; ?>
                <tr<?= $times === null ? '' : ' data-vp-times="'
                    . h($times) . '"' ?>>
                    <td class="font-monospace"><?= h($row['from'] === ''
                        ? '—' : $row['from']) ?></td>
                    <td><?= h($row['type'] === ''
                        ? '—' : $row['type']) ?></td>
                    <td class="font-monospace"><?= h($row['to']) ?></td>
                    <td><?= h($row['first'] === null
                        ? '—' : date('Y-m-d', $row['first'])) ?></td>
                    <td><?= h($row['last'] === null
                        ? '—' : date('Y-m-d', $row['last'])) ?></td>
                    <td class="text-end"><?= h($row['count'] > 1
                        ? number_format($row['count']) : '') ?></td>
                    <td class="font-monospace vp-rf-dim"><?=
                        $this->element('Values/Renderers/source_cell',
                            array('sources' => $row['sources'])
                        ) ?></td>
                </tr>
            <?php endforeach; ?>
        </tbody>
    </table>
</div>
