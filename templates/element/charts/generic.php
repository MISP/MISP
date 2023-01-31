<?php

$chartOptions = $chartOptions ?? [];
$seed = mt_rand();
$chartId = "chart-{$seed}";

$chartData = $chartData ?? [];
$chartSeries = [];
if (!empty($series)) {
    $chartSeries = $series;
}
?>

<div id="<?= $chartId ?>"></div>

<script>
    $(document).ready(function() {
        const passedOptions = <?= json_encode($chartOptions) ?>;
        const defaultOptions = {
            chart: {
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
            }
            series: <?= json_encode($chartSeries) ?>,
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