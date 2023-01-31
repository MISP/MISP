<?php

$chartOptions = $chartOptions ?? [];
$seed = mt_rand();
$chartId = "chart-{$seed}";

$data = $data ?? [];
$series = [];
$labels = [];
$totalValue = 0;
foreach ($data as $combined) {
    $combinedValues = array_values($combined);
    $label = $combinedValues[0];
    $value = $combinedValues[1];
    $labels[] = $label;
    $series[] = $value;
    $totalValue += $value;
}
?>

<div id="<?= $chartId ?>"></div>

<script>
    $(document).ready(function() {
        const totalValue = <?= $totalValue ?>;
        const passedOptions = <?= json_encode($chartOptions) ?>;
        const defaultOptions = {
            chart: {
                id: '<?= $chartId ?>',
                type: 'pie',
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
            series: <?= json_encode($series) ?>,
            labels: <?= json_encode($labels) ?>,
            tooltip: {
                y: {
                    formatter: function(value, {
                        series,
                        seriesIndex,
                        dataPointIndex,
                        w
                    }) {
                        return value + " (" + (value / totalValue * 100).toFixed(2) + "%)"
                    }
                }
            },
            noData: {
                text: '<?= __('No data') ?>',
                verticalAlign: 'bottom',
                style: {
                    fontFamily: 'var(--bs-body-font-family)'
                }
            }
        }
        const chartOptions = mergeDeep({}, defaultOptions, passedOptions)
        new ApexCharts(document.querySelector('#<?= $chartId ?>'), chartOptions).render();
    })
</script>

<style>
    #<?= $chartId ?>.apexcharts-tooltip-y-group {
        padding: 1px;
    }
</style>