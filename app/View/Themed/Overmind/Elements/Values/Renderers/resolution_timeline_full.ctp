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
 * Every column sorts from its heading: ascending, descending, then back
 * to the most recent first. On the value page the list engine does it;
 * on the event page, event-object-views.js.
 *
 * @var array $data
 */
$periods = $data['periods'] ?? array();
$peak = empty($periods) ? 0 : max(array_column($periods, 'count'));
$drawn = $data['dated'] && $peak > 0 && count($periods) > 1;
// The brush runs on the value page's list engine; elsewhere the strip is
// only read.
$listed = empty($this->viewVars['vpEventScope']);
$brushed = $drawn && $listed;
$columns = array(
    'name' => array(__('Name'), ''),
    'type' => array(__('Type'), ''),
    'to' => array(__('Resolves to'), ''),
    'first' => array(__('First'), ''),
    'last' => array(__('Last'), ''),
    'seen' => array(__('Seen'), 'text-end'),
    'source' => array(__('Source'), ''),
);
// Addresses by their bytes, so 9.x comes before 10.x, then names.
$addressKey = function ($text) {
    if ($text === '') {
        return '';
    }
    if (filter_var($text, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        return '04' . bin2hex(inet_pton($text));
    }
    if (filter_var($text, FILTER_VALIDATE_IP)) {
        return '06' . bin2hex(inet_pton($text));
    }
    return '1' . strtolower($text);
};
$dateKey = function ($time) {
    return $time === null ? '' : date('YmdHis', $time);
};
// Tokens compare as strings and an empty one sorts last both ways; the
// source sorts by what its cell prints, `#9` before `#10`.
$rowSort = function ($row, $index, $source) use ($addressKey, $dateKey) {
    $source = strtolower(trim(html_entity_decode(
        strip_tags($source),
        ENT_QUOTES | ENT_HTML5
    )));
    $source = preg_replace_callback('/\d+/', function ($digits) {
        return str_pad($digits[0], 12, '0', STR_PAD_LEFT);
    }, $source);
    $keys = array(
        'name' => $addressKey($row['from']),
        'type' => strtolower($row['type']),
        'to' => $addressKey($row['to']),
        'first' => $dateKey($row['first']),
        'last' => $dateKey($row['last']),
        'seen' => str_pad((string)(int)$row['count'], 12, '0', STR_PAD_LEFT),
        'source' => $source,
        'default' => str_pad((string)$index, 6, '0', STR_PAD_LEFT),
    );
    $out = '';
    foreach ($keys as $key => $token) {
        $out .= ' data-vp-sort-' . $key . '="' . h($token) . '"';
    }
    return $out;
};
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
<div class="vp-rf vp-rf-res"<?= $listed ? ' data-vp-list' : '' ?>>
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

    <table class="table table-sm vp-rf-table"<?= $listed
        ? ' data-vp-list-rows' : '' ?>>
        <thead>
            <tr>
                <?php foreach ($columns as $key => $column): ?>
                    <th scope="col"<?= $column[1] === ''
                        ? '' : ' class="' . $column[1] . '"' ?>>
                        <button type="button" class="vp-th-sort"
                                data-vp-sort-col="<?= h($key) ?>">
                            <span class="sortable-header"><?=
                                h($column[0])
                            ?><i class="sort-icon"></i></span>
                        </button>
                    </th>
                <?php endforeach; ?>
            </tr>
        </thead>
        <tbody>
            <?php foreach ($data['resolutions'] as $index => $row): ?>
                <?php
                $times = $brushed ? $stamp($row) : null;
                $source = $this->element('Values/Renderers/source_cell',
                    array('sources' => $row['sources'])
                );
                ?>
                <tr<?= $times === null ? '' : ' data-vp-times="'
                    . h($times) . '"' ?><?=
                    $rowSort($row, $index, $source) ?>>
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
                        $source ?></td>
                </tr>
            <?php endforeach; ?>
        </tbody>
    </table>
</div>
