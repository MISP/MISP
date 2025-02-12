<?php

$chartOptions = $chartOptions ?? [];
$seed = mt_rand();
$chartId = "chart-{$seed}";

$chartData = $chartData ?? [];
$chartSeries = [];
if (!empty($series)) {
    $chartSeries = $series;
} else {
    // Transform the chart data into the expected format
    $data = [];
    foreach ($chartData as $i => $entry) {
        $data[] = $entry['count'];
    }
    $chartSeries = [
        ['data' => $data]
    ];
}
?>

<div id="<?= $chartId ?>"></div>

<script>
    $(document).ready(function() {
        const passedOptions = <?= json_encode($chartOptions) ?>;
        const defaultOptions = {
            chart: {
                id: '<?= $chartId ?>',
                type: 'line',
                sparkline: {
                    enabled: true
                },
                dropShadow: {
                    enabled: true,
                    top: 1,
                    left: 1,
                    blur: 2,
                    opacity: 0.2,
                },
                animations: {
                    enabled: false
                },
            },
            series: <?= json_encode($chartSeries) ?>,
            tooltip: {
                theme: 'dark'
            },
        }
        const chartOptions = mergeDeep({}, defaultOptions, passedOptions)
        new ApexCharts(document.querySelector('#<?= $chartId ?>'), chartOptions).render();
    })
</script>

<style>
    #<?= $chartId ?> .apexcharts-tooltip-y-group {
        padding: 1px;
    }
</style>