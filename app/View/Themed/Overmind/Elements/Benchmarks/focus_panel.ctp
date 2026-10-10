<?php
/*
 * Benchmarks for one pinned key — the shape the User view's tab needs.
 *
 * The generic index answers "who is the most expensive?", so it carries a
 * Scope switcher and repeats the scope and the key on every row. Pin both
 * (scope:user/key:5) and that is all noise: the interesting question becomes
 * "what does this one cost, and is it getting worse?". This renders that —
 * four metric pills over the window, then one row per day.
 *
 * Expected variables:
 *   $data     array   the controller's flat rows (scope, field, date, key,
 *                     text, value, unit), already filtered to the one key
 *   $filters  array   the harvested filters, `average` and `days` read here
 *   $baseurl  string
 *
 * Rendered by Benchmarks/index.ctp whenever scope and key are both pinned.
 */

$isAverage = !empty($filters['average']);
$keyLabel = $data[0]['text'] ?? ('#' . $filters['key']);
$scope = $filters['scope'];

$metrics = [
    'time' => [
        'label' => __('Wall time'),
        'icon' => 'fas fa-stopwatch',
        'color' => '#1892B1',
        'note' => __('How long the request took from start to response.'),
    ],
    'sql_time' => [
        'label' => __('SQL time'),
        'icon' => 'fas fa-database',
        'color' => '#8B5CF6',
        'note' => __('The share of that spent waiting on the database.'),
    ],
    'sql_queries' => [
        'label' => __('SQL queries'),
        'icon' => 'fas fa-layer-group',
        'color' => '#F59E0B',
        'note' => __('How many statements one request ran.'),
    ],
    'memory' => [
        'label' => __('Peak memory'),
        'icon' => 'fas fa-memory',
        'color' => '#DB6A47',
        'note' => __('The high-water mark of the PHP process.'),
    ],
];

// Each metric carries its own unit, so a shared "round to 2" would print
// `0 s` for a 300ms request and `1234.56 ms` for a slow query batch.
$fmt = function ($field, $value) {
    if ($value === null || $value === '') {
        return '—';
    }
    $value = (float)$value;
    switch ($field) {
        case 'time':
            return $value < 1
                ? round($value * 1000) . ' ms'
                : round($value, 2) . ' s';
        case 'sql_time':
            return $value >= 1000
                ? round($value / 1000, 2) . ' s'
                : round($value, 1) . ' ms';
        case 'sql_queries':
            return fmod($value, 1.0) === 0.0
                ? number_format($value)
                : number_format($value, 1);
        case 'memory':
            return round($value, 1) . ' MB';
    }
    return (string)$value;
};

/* The controller hands back one row per (field, date). Pivot to date ↦ field
 * so a day is a row rather than four of them. `aggregate:1` collapses every
 * day into the pseudo-date 'aggregate', which is why the tab asks for the
 * daily breakdown and sums here instead. */
$byDate = [];
foreach ($data as $row) {
    $byDate[$row['date']][$row['field']] = $row['value'];
}
krsort($byDate);
$isAggregated = (count($byDate) === 1 && isset($byDate['aggregate']));

// Summary over the window: a mean of the daily per-request averages in
// average mode, a straight sum of the daily totals otherwise.
$summary = [];
foreach (array_keys($metrics) as $field) {
    $values = [];
    foreach ($byDate as $fields) {
        if (isset($fields[$field])) {
            $values[] = (float)$fields[$field];
        }
    }
    if (empty($values)) {
        $summary[$field] = null;
    } else {
        $summary[$field] = $isAverage
            ? array_sum($values) / count($values)
            : array_sum($values);
    }
}

// Toggle links keep every other pinned filter, flipping only `average`.
$linkFor = function ($average) use ($baseurl, $filters) {
    $url = $baseurl . '/benchmarks/index';
    foreach (['scope', 'field', 'key', 'days', 'aggregate'] as $name) {
        if (!empty($filters[$name])) {
            $url .= '/' . $name . ':' . rawurlencode($filters[$name]);
        }
    }
    return $url . '/average:' . ($average ? '1' : '0');
};

$dayCount = $isAggregated ? null : count($byDate);
?>

<div class="container-fluid">

    <!-- WHAT THIS IS -->
    <div class="card shadow-sm mb-4">
        <div class="card-body d-flex flex-wrap align-items-start justify-content-between gap-3">
            <div style="min-width:0; max-width:46rem;">
                <div class="text-muted small text-uppercase fw-bold mb-1">
                    <?= h(__('Benchmarks')) ?>
                </div>
                <div class="fw-semibold mb-1"><?= h($keyLabel) ?></div>
                <p class="text-muted small mb-0">
                    <?= __('While the benchmarking plugin is on, MISP records the cost of every request and adds it up per day and per %s. These are the four figures it keeps.', h($scope)) ?>
                    <?php if (!empty($byDate)): ?>
                        <?= $isAverage
                            ? __('You are looking at the average one request cost.')
                            : __('You are looking at the total spent across all requests.') ?>
                    <?php endif; ?>
                </p>
                <?php if (empty($byDate)): ?>
                    <p class="text-muted small mb-0 mt-2 fst-italic">
                        <?= __('No request by this %s has been measured yet.', h($scope)) ?>
                    </p>
                <?php endif; ?>
            </div>

            <?php if (!empty($byDate)): ?>
                <div class="flex-shrink-0">
                    <div class="text-muted small text-uppercase fw-bold mb-1"><?= h(__('Mode')) ?></div>
                    <div class="btn-group btn-group-sm" role="group" aria-label="<?= h(__('Mode')) ?>">
                        <a href="<?= h($linkFor(false)) ?>" data-bench-filter
                           class="btn <?= $isAverage ? 'btn-outline-secondary' : 'btn-primary' ?>">
                            <?= h(__('Total')) ?>
                        </a>
                        <a href="<?= h($linkFor(true)) ?>" data-bench-filter
                           class="btn <?= $isAverage ? 'btn-primary' : 'btn-outline-secondary' ?>">
                            <?= h(__('Average / request')) ?>
                        </a>
                    </div>
                    <?php if ($dayCount !== null): ?>
                        <div class="text-muted mt-2" style="font-size:.7rem;">
                            <?= h(__n('%d day recorded', '%d days recorded', $dayCount, $dayCount)) ?>
                        </div>
                    <?php endif; ?>
                </div>
            <?php endif; ?>
        </div>
    </div>

    <?php if (!empty($byDate)): ?>

        <!-- SUMMARY PILLS -->
        <div class="row g-3 mb-4">
            <?php foreach ($metrics as $field => $meta): ?>
                <div class="col-6 col-md-3">
                    <?= $this->element('genericElementsBS5/Stats/metric_pill', [
                        'icon' => $meta['icon'],
                        'color' => $meta['color'],
                        'label' => $meta['label'],
                        'value' => $fmt($field, $summary[$field]),
                    ]) ?>
                    <div class="text-muted mt-1 px-1" style="font-size:.7rem; line-height:1.3;">
                        <?= h($meta['note']) ?>
                    </div>
                </div>
            <?php endforeach; ?>
        </div>

        <!-- PER-DAY BREAKDOWN -->
        <?php if (!$isAggregated): ?>
            <div class="card shadow-sm mb-4">
                <div class="card-body p-0">
                    <div class="table-responsive">
                        <table class="table table-hover align-middle mb-0">
                            <thead>
                                <tr>
                                    <th><?= h(__('Date')) ?></th>
                                    <?php foreach ($metrics as $meta): ?>
                                        <th class="text-end"><?= h($meta['label']) ?></th>
                                    <?php endforeach; ?>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($byDate as $date => $fields): ?>
                                    <tr>
                                        <td class="font-monospace"><?= h($date) ?></td>
                                        <?php foreach (array_keys($metrics) as $field): ?>
                                            <td class="text-end">
                                                <?= h($fmt($field, $fields[$field] ?? null)) ?>
                                            </td>
                                        <?php endforeach; ?>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        <?php endif; ?>

    <?php endif; ?>

</div>

