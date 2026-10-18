<?php
/**
 * Statistics attribute types tab: the attribute types each organisation's
 * events hold, from the attribute histogram REST statistics, drawn client-side.
 */
$uid = 'stats-histogram-' . mt_rand();
?>
<div class="card shadow-sm mb-3" id="<?= h($uid) ?>">
    <div class="card-header d-flex align-items-center gap-3">
        <span class="fw-semibold"><?= __('Attribute types per organisation') ?></span>
        <span class="small text-body-secondary" data-histogram-summary></span>
        <select class="form-select form-select-sm ms-auto" style="max-width: 11rem;" data-histogram-limit aria-label="<?= h(__('Organisations shown')) ?>">
            <option value="20"><?= __('Top 20 organisations') ?></option>
            <option value="50"><?= __('Top 50 organisations') ?></option>
            <option value="0"><?= __('All organisations') ?></option>
        </select>
    </div>
    <div class="card-body">
        <div data-histogram-loading><?= $this->element('genericElementsBS5/loader') ?></div>
        <div style="position: relative;" data-histogram-box hidden><canvas data-histogram-chart></canvas></div>
    </div>
</div>
<script>
(function () {
    var root = document.getElementById(<?= json_encode($uid) ?>);
    var text = <?= json_encode([
        'failed' => __('Could not load the attribute statistics.'),
        'none' => __('No attributes yet.'),
        'other' => __('Other types'),
        'summary' => __('%s attributes, %s organisations creating events'),
    ]) ?>;
    var PALETTE = [
        '#3B82F6','#10B981','#F59E0B','#EF4444','#8B5CF6',
        '#EC4899','#14B8A6','#F97316','#6366F1','#84CC16'
    ];
    var OTHER_COLOUR = '#94A3B8';
    var rows = [];
    var types = [];
    var chart = null;

    fetch(<?= json_encode($baseurl . '/users/statistics/attributehistogram.json') ?>, {
        credentials: 'same-origin',
        headers: {'Accept': 'application/json', 'X-Requested-With': 'XMLHttpRequest'}
    }).then(function (res) {
        if (!res.ok) throw new Error('HTTP ' + res.status);
        return res.json();
    }).then(function (data) {
        root.querySelector('[data-histogram-loading]').remove();
        // The first row, the largest, is all organisations together
        var all = data[0] || {data: {}, total: 0};
        rows = data.slice(1).filter(function (row) { return +row.total > 0; });
        root.querySelector('[data-histogram-summary]').textContent = text.summary
            .replace('%s', (+all.total).toLocaleString())
            .replace('%s', rows.length.toLocaleString());
        if (!rows.length) {
            root.querySelector('.card-body').textContent = text.none;
            return;
        }
        types = Object.keys(all.data).sort(function (a, b) { return all.data[b] - all.data[a]; }).slice(0, PALETTE.length);
        root.querySelector('[data-histogram-limit]').addEventListener('change', render);
        render();
    }).catch(function () {
        root.querySelector('.card-body').textContent = text.failed;
    });

    function render() {
        var limit = +root.querySelector('[data-histogram-limit]').value;
        var shown = limit ? rows.slice(0, limit) : rows;
        var datasets = types.map(function (type, i) {
            return {
                label: type,
                backgroundColor: PALETTE[i],
                data: shown.map(function (row) { return +(row.data[type] || 0); })
            };
        });
        datasets.push({
            label: text.other,
            backgroundColor: OTHER_COLOUR,
            data: shown.map(function (row) {
                return types.reduce(function (rest, type) { return rest - (+(row.data[type] || 0)); }, +row.total);
            })
        });
        var box = root.querySelector('[data-histogram-box]');
        box.hidden = false;
        box.style.height = (shown.length * 24 + 90) + 'px';
        if (chart) chart.destroy();
        var css = getComputedStyle(root);
        var textColour = css.getPropertyValue('--bs-body-color').trim();
        var gridColour = css.getPropertyValue('--bs-border-color-translucent').trim();
        chart = new Chart(root.querySelector('[data-histogram-chart]'), {
            type: 'bar',
            data: {labels: shown.map(function (row) { return row.org_name; }), datasets: datasets},
            options: {
                indexAxis: 'y',
                maintainAspectRatio: false,
                responsive: true,
                scales: {
                    x: {stacked: true, grid: {color: gridColour}, ticks: {color: textColour, callback: function (v) { return (+v).toLocaleString(); }}},
                    y: {stacked: true, grid: {color: gridColour}, ticks: {color: textColour, autoSkip: false}}
                },
                plugins: {
                    legend: {position: 'top', labels: {color: textColour, boxWidth: 10, boxHeight: 10}},
                    tooltip: {mode: 'index', intersect: false, filter: function (item) { return item.raw > 0; }}
                }
            }
        });
    }
})();
</script>
