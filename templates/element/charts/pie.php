<?php

use Cake\Utility\Inflector;

$chartOptions = $chartOptions ?? [];
$seed = mt_rand();
$chartId = "chart-{$seed}";

$firstElement = reset($data);
if (!is_array($firstElement)) { // convert the K-V into list of tuple
    $tupleList = [];
    foreach ($data as $k => $v) {
        $tupleList[] = [$k, $v];
    }
    $data = $tupleList;
}

$data = $data ?? [];
$series = [];
$labels = [];
$totalValue = 0;
foreach ($data as $combined) {
    $combinedValues = array_values($combined);
    $label = strval($combinedValues[0]);
    if (is_bool($combinedValues[0])) {
        $label = sprintf('%s: %s', h(Inflector::humanize(array_key_first($combined))), empty($combinedValues[0]) ? __('False') : __('True'));
    }
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
                    opacity: 0.15,
                },
                animations: {
                    enabled: true,
                    speed: 200,
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
            },
            stroke: {
                width: 1
            }
        }
        const chartOptions = mergeDeep({}, defaultOptions, passedOptions)

        if (chartOptions?.plotOptions?.pie?.donut?.labels?.total?.formatter) {
            chartOptions.plotOptions.pie.donut.labels.total.formatter = window[chartOptions.plotOptions.pie.donut.labels.total.formatter]
        }

        new ApexCharts(document.querySelector('#<?= $chartId ?>'), chartOptions).render();
    })
</script>

<style>
    #<?= $chartId ?>.apexcharts-tooltip-y-group {
        /* padding: 1px; */
    }
</style>