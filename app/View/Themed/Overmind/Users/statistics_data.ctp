<?php
/**
 * Statistics overview tab.
 *
 * $stats          UsersController::__statisticsData() figures, as strings
 * $userStatistics users, local and remote organisations: total, year, month
 * $showActivity   false while the organisation index is hidden from the user
 */
$n = function ($value) {
    return number_format((int)$value);
};
$monthly = function ($label, $value) use ($n) {
    return $label . ' · ' . __('+%s this month', $n($value));
};
$pill = function (array $pill) {
    return '<div class="col-6 col-md-4 col-xxl-3">'
        . $this->element('genericElementsBS5/Stats/metric_pill', $pill)
        . '</div>';
};
$pgpShare = (int)$stats['user_count'] > 0
    ? round(100 * (int)$stats['user_count_pgp'] / (int)$stats['user_count'], 1)
    : 0;
$activityId = 'stats-activity-' . mt_rand();
?>
<div class="card shadow-sm mb-3">
    <div class="card-header fw-semibold"><?= __('Data') ?></div>
    <div class="card-body">
        <div class="row g-3">
            <?= $pill(['icon' => 'misp-icon misp-icon-event misp-simple', 'color' => '#1892B1', 'label' => $monthly(__('Events'), $stats['event_count_month']), 'value' => $n($stats['event_count'])]) ?>
            <?= $pill(['icon' => 'misp-icon misp-icon-attribute misp-simple', 'color' => '#97CC04', 'label' => $monthly(__('Attributes'), $stats['attribute_count_month']), 'value' => $n($stats['attribute_count'])]) ?>
            <?= $pill(['icon' => 'misp-icon misp-icon-object misp-simple', 'color' => '#524948', 'label' => $monthly(__('Objects'), $stats['object_count_month']), 'value' => $n($stats['object_count'])]) ?>
            <?= $pill(['icon' => 'misp-icon misp-icon-report misp-simple', 'color' => '#4DA167', 'label' => $monthly(__('Event reports'), $stats['eventreport_count_month']), 'value' => $n($stats['eventreport_count'])]) ?>
            <?= $pill(['icon' => 'misp-icon misp-icon-analyst-note misp-simple', 'color' => '#8F2D56', 'label' => $monthly(__('Analyst data'), $stats['analyst_data_count_month']), 'value' => $n($stats['analyst_data_count'])]) ?>
            <?= $pill(['icon' => 'fas fa-diagram-project', 'color' => '#E67F0D', 'label' => __('Correlations'), 'value' => $n($stats['correlation_count'])]) ?>
            <?= $pill(['icon' => 'fas fa-comment-dots', 'color' => '#DB6A47', 'label' => __('Active proposals'), 'value' => $n($stats['proposal_count'])]) ?>
            <?= $pill(['icon' => 'fas fa-layer-group', 'color' => '#6366F1', 'label' => __('Attributes / objects per event'), 'value' => $n($stats['attributes_per_event']) . ' / ' . $n($stats['objects_per_event'])]) ?>
        </div>
    </div>
</div>

<div class="card shadow-sm mb-3">
    <div class="card-header fw-semibold"><?= __('Community') ?></div>
    <div class="card-body">
        <div class="row g-3 mb-3">
            <?= $pill(['icon' => 'fas fa-user', 'color' => '#3B82F6', 'label' => __('Users'), 'value' => $n($stats['user_count'])]) ?>
            <?= $pill(['icon' => 'fas fa-key', 'color' => '#14B8A6', 'label' => __('Users with a PGP key'), 'value' => $n($stats['user_count_pgp']) . ' (' . $pgpShare . '%)']) ?>
            <?= $pill(['icon' => 'fas fa-building', 'color' => '#F59E0B', 'label' => __('Organisations'), 'value' => $n($stats['org_count'])]) ?>
            <?= $pill(['icon' => 'fas fa-house', 'color' => '#EC4899', 'label' => __('Local organisations'), 'value' => $n($stats['local_org_count'])]) ?>
            <?= $pill(['icon' => 'fas fa-pen-nib', 'color' => '#8B5CF6', 'label' => __('Organisations creating events'), 'value' => $n($stats['contributing_org_count'])]) ?>
            <?= $pill(['icon' => 'fas fa-people-group', 'color' => '#06B6D4', 'label' => __('Users per local organisation'), 'value' => $stats['average_user_per_org']]) ?>
        </div>
        <table class="table table-sm align-middle mb-0">
            <thead>
                <tr>
                    <th></th>
                    <th class="text-end"><?= __('Total') ?></th>
                    <th class="text-end"><?= __('New this year') ?></th>
                    <th class="text-end"><?= __('New this month') ?></th>
                </tr>
            </thead>
            <tbody>
                <?php
                $rows = [
                    'user' => __('Users'),
                    'org_local' => __('Local organisations'),
                    'org_external' => __('Known remote organisations'),
                ];
                foreach ($rows as $scope => $label):
                    $counts = $userStatistics[$scope]['data'];
                ?>
                <tr>
                    <td><?= h($label) ?></td>
                    <td class="text-end fw-semibold"><?= $n($counts['total']) ?></td>
                    <?php foreach (['year', 'month'] as $range): ?>
                    <td class="text-end <?= (int)$counts[$range] > 0 ? 'text-success fw-semibold' : 'text-body-secondary' ?>">
                        <?= (int)$counts[$range] > 0 ? '+' . $n($counts[$range]) : '0' ?>
                    </td>
                    <?php endforeach; ?>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</div>

<?php if ($showActivity): ?>
<div class="card shadow-sm mb-3">
    <div class="card-header fw-semibold"><?= __('Activity') ?></div>
    <div class="card-body">
        <p class="small text-body-secondary mb-3"><?= __('Log entries per day over the last 18 weeks, all organisations together: when the community is most active.') ?></p>
        <div id="<?= h($activityId) ?>" class="ov-activity">
            <?= $this->element('genericElementsBS5/loader') ?>
        </div>
    </div>
</div>
<style>
    .ov-activity { overflow-x: auto; }
    .ov-activity-months, .ov-activity-grid { display: grid; grid-auto-flow: column; grid-auto-columns: 14px; gap: 3px; margin-left: 2.2rem; }
    .ov-activity-months { font-size: .7rem; color: var(--bs-secondary-color); height: 1.1rem; }
    .ov-activity-months span { white-space: nowrap; overflow: visible; }
    .ov-activity-body { display: flex; }
    .ov-activity-days { display: grid; grid-template-rows: repeat(7, 14px); gap: 3px; width: 2.2rem; font-size: .65rem; color: var(--bs-secondary-color); }
    .ov-activity-body .ov-activity-grid { grid-template-rows: repeat(7, 14px); margin-left: 0; }
    .ov-activity-cell { width: 14px; height: 14px; border-radius: 3px; background: var(--bs-tertiary-bg); }
    .ov-activity-cell[data-level="1"] { background: color-mix(in srgb, var(--bs-info) 25%, var(--bs-body-bg)); }
    .ov-activity-cell[data-level="2"] { background: color-mix(in srgb, var(--bs-info) 50%, var(--bs-body-bg)); }
    .ov-activity-cell[data-level="3"] { background: color-mix(in srgb, var(--bs-info) 75%, var(--bs-body-bg)); }
    .ov-activity-cell[data-level="4"] { background: var(--bs-info); }
    .ov-activity-cell.is-future { background: transparent; }
    .ov-activity-legend { display: flex; align-items: center; gap: 3px; font-size: .7rem; color: var(--bs-secondary-color); margin: .5rem 0 0 2.2rem; }
    .ov-activity-legend .ov-activity-cell { width: 11px; height: 11px; }
</style>
<script>
(function () {
    var host = document.getElementById(<?= json_encode($activityId) ?>);
    var text = <?= json_encode([
        'failed' => __('Could not load the activity.'),
        'entries' => __('%s log entries'),
        'none' => __('No log entries'),
        'less' => __('Less'),
        'more' => __('More'),
        'mon' => __('Mon'),
        'wed' => __('Wed'),
        'fri' => __('Fri'),
    ]) ?>;
    fetch(<?= json_encode($baseurl . '/users/statistics/activity.json') ?>, {
        credentials: 'same-origin',
        headers: {'Accept': 'application/json', 'X-Requested-With': 'XMLHttpRequest'}
    }).then(function (res) {
        if (!res.ok) throw new Error('HTTP ' + res.status);
        return res.json();
    }).then(draw).catch(function () {
        host.innerHTML = '<div class="small text-body-secondary">' + text.failed + '</div>';
    });

    function day(iso) {
        var p = iso.split('-');
        return new Date(Date.UTC(+p[0], +p[1] - 1, +p[2]));
    }

    function draw(data) {
        var days = data.days || {};
        var values = Object.keys(days).map(function (k) { return days[k]; }).sort(function (a, b) { return a - b; });
        var cuts = [0.25, 0.5, 0.75].map(function (q) { return values[Math.floor(q * (values.length - 1))] || 0; });
        var level = function (v) {
            if (!v) return 0;
            for (var i = 0; i < cuts.length; i++) {
                if (v <= cuts[i]) return i + 1;
            }
            return 4;
        };
        var months = document.createElement('div');
        months.className = 'ov-activity-months';
        var grid = document.createElement('div');
        grid.className = 'ov-activity-grid';
        var to = day(data.to);
        var lastMonth = null;
        for (var d = day(data.from); d <= to || d.getUTCDay() !== 1; d = new Date(d.getTime() + 86400000)) {
            var iso = d.toISOString().slice(0, 10);
            if (d.getUTCDay() === 1) {
                var label = document.createElement('span');
                if (d.getUTCMonth() !== lastMonth) {
                    label.textContent = d.toLocaleString(undefined, {month: 'short', timeZone: 'UTC'});
                    lastMonth = d.getUTCMonth();
                }
                months.appendChild(label);
            }
            var cell = document.createElement('div');
            cell.className = 'ov-activity-cell';
            if (d > to) {
                cell.classList.add('is-future');
            } else {
                var v = days[iso] || 0;
                cell.dataset.level = level(v);
                cell.title = iso + ': ' + (v ? text.entries.replace('%s', v.toLocaleString()) : text.none);
            }
            grid.appendChild(cell);
        }
        var labels = document.createElement('div');
        labels.className = 'ov-activity-days';
        ['mon', '', 'wed', '', 'fri', '', ''].forEach(function (key) {
            var span = document.createElement('span');
            span.textContent = key ? text[key] : '';
            labels.appendChild(span);
        });
        var body = document.createElement('div');
        body.className = 'ov-activity-body';
        body.appendChild(labels);
        body.appendChild(grid);
        var legend = document.createElement('div');
        legend.className = 'ov-activity-legend';
        legend.append(text.less);
        for (var l = 0; l <= 4; l++) {
            var swatch = document.createElement('span');
            swatch.className = 'ov-activity-cell';
            swatch.dataset.level = l;
            legend.appendChild(swatch);
        }
        legend.append(text.more);
        host.replaceChildren(months, body, legend);
    }
})();
</script>
<?php endif; ?>
