<?php
$seed = 's-' . mt_rand();
$variationIcon = '';
$variationClass = '';
if (!is_null($variation)) {
    if ($variation == 0) {
        $variationIcon = $this->FontAwesome->getClass('minus');
    } elseif ($variation > 0) {
        $variationIcon = 'trends-arrow-up-white fs-6';
        $variationClass = 'bg-success';
    } else {
        $variationIcon = 'trends-arrow-up-white fs-6 fa-rotate-180 fa-flip-vertical';
        $variationClass = 'bg-danger';
    }
}

$series = [];
$statistics_day_number = '';
if (!empty($timeline['created']['timeline'])) {
    $statistics_day_number = $timeline['created']['days'];
    $i = count($series);
    $series[$i]['name'] = __('Created');
    $series[$i]['type'] = !empty($chartType) ? $chartType : 'column';
    foreach ($timeline['created']['timeline'] as $entry) {
        $series[$i]['data'][] = ['x' => $entry['time'], 'y' => $entry['count']];
    }
}
if (!empty($timeline['modified']['timeline'])) {
    $statistics_day_number = empty($statistics_day_number) ? $timeline['modified']['days'] : $statistics_day_number;
    $i = count($series);
    $series[$i]['name'] = __('Modified');
    $series[$i]['type'] = !empty($chartType) ? $chartType : 'line';
    foreach ($timeline['modified']['timeline'] as $entry) {
        $series[$i]['data'][] = ['x' => $entry['time'], 'y' => $entry['count']];
    }
}

$variationHtml = '';
if (!is_null($variation)) {
    $variationHtml = sprintf(
        '<div class="badge %s fw-bold"><span class="%s me-2 align-middle"></span>%s</div>',
        $variationClass,
        $variationIcon,
        !is_null($variation) ? h($variation) : ''
    );
}

$titleHtml = isset($title) ? h($title) : ($titleHtml ?? '');
$leftContent = sprintf(
    '<div class="">%s</div><h2 class="my-2 text-nowrap">%s <span class="fs-8 fw-light">%s</span></h2>%s',
    $titleHtml,
    h($number ?? ''),
    __('Past {0} days', $statistics_day_number),
    $variationHtml
);
$rightContent = sprintf('<div class="">%s</div>', $this->element('charts/bar', [
    'series' => $series,
    'chartOptions' => array_merge(
        [
            'chart' => [
                'height' => '90px',
            ],
            'stroke' => [
                'width' => [0, 2],
                'curve' => 'smooth',
            ],
        ],
        !empty($chartOptions) ? $chartOptions : []
    )
]));
$cardContent = sprintf(
    '<div class="highlight-panel-container d-flex align-items-center justify-content-between %s" style="%s"><div class="number-container">%s</div><div class="chart-container w-50">%s</div></div>',
    $panelClasses ?? '',
    $panelStyle ?? '',
    $leftContent,
    $rightContent
);

echo $this->Bootstrap->card([
    'variant' => 'secondary',
    'bodyHTML' => $cardContent,
    'bodyClass' => 'p-3',
    'class' => ['shadow-sm', (empty($panelNoGrow) ? 'grow-on-hover' : '')]
]);

?>
