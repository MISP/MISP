<?php

$statisticsHtml = '';
if (empty($timeline['created']) && empty($timeline['modified'])) {
    return $statisticsHtml;
}


$seed = 'timeline-' . mt_rand();
$title = __('Activity');
$statistics_day_number = $timeline['created']['days'];
$subTitle = __('Past {0} days', $statistics_day_number);

$series = [];
if (!empty($timeline['created']['timeline'])) {
    $series[0]['name'] = __('Created');
    foreach ($timeline['created']['timeline'] as $entry) {
        $series[0]['data'][] = ['x' => $entry['time'], 'y' => $entry['count']];
    }
}
if (!empty($timeline['modified']['timeline'])) {
    $series[1]['name'] = __('Modified');
    foreach ($timeline['modified']['timeline'] as $entry) {
        $series[1]['data'][] = ['x' => $entry['time'], 'y' => $entry['count']];
    }
}

$panelControlHtml = sprintf(
    '<div class="text-nowrap">
        %s <span class="fs-8 fw-light">%s</span>%s
    </div>',
    $title,
    $subTitle,
    $this->Bootstrap->button([
        'variant' => 'link',
        'icon' => 'cog',
        'size' => 'xs',
        'nodeType' => 'a',
        'onclick' => '',
        'class' => ['btn-statistics-days-configurator-' . $seed,],
        'params' => [
            'data-bs-toggle' => 'popover',
        ]
    ])
);
$createdNumber = empty($timeline['created']) ? '' : sprintf(
    '<div class="lh-1 d-flex align-items-center" title="%s">%s<span class="ms-1"> %s</span></div>',
    __('{0} Created', $timeline['created']['variation']),
    $this->Bootstrap->icon('plus', ['class' => ['fa-fw'], 'params' => ['style' => 'font-size: 60%;']]),
    $timeline['created']['variation']
);
$modifiedNumber = empty($timeline['modified']) ? '' : sprintf(
    '<div class="lh-1 d-flex align-items-center" title="%s">%s<span class="ms-1"> %s</span></div>',
    __('{0} Modified', $timeline['modified']['variation']),
    $this->Bootstrap->icon('edit', ['class' => ['fa-fw'], 'params' => ['style' => 'font-size: 60%;']]),
    $timeline['modified']['variation']
);
$activityNumbers = sprintf('<div class="my-1 fs-5">%s%s</div>', $createdNumber, $modifiedNumber);

$leftContent = sprintf(
    '%s%s',
    $panelControlHtml,
    $activityNumbers
);
$rightContent = sprintf('<div class="">%s</div>', $this->element('charts/bar', [
    'series' => $series,
    'chartOptions' => array_merge(
        [
            'chart' => [
                'height' => 60,
            ],
            'stroke' => [
                'width' => 2,
                'curve' => 'smooth',
            ],
        ],
        !empty($chartOptions) ? $chartOptions : []
    )
]));
$cardContent = sprintf(
    '<div class="highlight-panel-container d-flex align-items-center justify-content-between" style="max-height: 100px">
        <div class="number-container">%s</div>
        <div class="chart-container p-2" style="width: 60%%;">%s</div>
    </div>',
    $leftContent,
    $rightContent
);

$card = $this->Bootstrap->card([
    'variant' => 'secondary',
    'bodyHTML' => $cardContent,
    'bodyClass' => 'py-1 px-2',
    'class' => ['shadow-sm', 'h-100']
]);

?>

<div class="col-sm-6 col-md-5 col-lg-4 col-xl-3 mb-1" style="min-height: 90px;"><?= $card ?></div>

<script>
    $(document).ready(function() {
        let popovers = new bootstrap.Popover(document.querySelector('.btn-statistics-days-configurator-<?= $seed ?>'), {
            container: 'body',
            html: true,
            sanitize: false,
            title: () => {
                return '<div class="d-flex align-items-center justify-content-between"> \
                            <?= __('Set spanning window') ?> \
                            <button type = "button" class="btn-xs btn-close" aria-label="Close"></button> \
                        </div>'
            },
            content: () => {
                return '<div class="input-group flex-nowrap"> \
                            <span class="input-group-text" id="addon-wrapping-<?= $seed ?>"><?= __('Days') ?></span> \
                            <input type="number" min="1" class="form-control" placeholder="7" aria-label="<?= __('Days') ?>" aria-describedby="addon-wrapping-<?= $seed ?>" value="<?= h($statistics_day_number) ?>"> \
                            <button class="btn btn-primary" type="button" onclick="statisticsDaysRedirect(this)"><?= __('Get statistics') ?> </button> \
                        </div>'
            }
        })
        document.querySelector('.btn-statistics-days-configurator-<?= $seed ?>').addEventListener('shown.bs.popover', function(evt) {
            const popover = bootstrap.Popover.getInstance(this)
            const popoverEl = popover.getTipElement()
            const popoverBtnCloseEl = popoverEl.querySelector('.popover-header button.btn-close')
            popoverBtnCloseEl.addEventListener('click', function() {
                popover.hide()
            })
        })
    })

    function statisticsDaysRedirect(clicked) {
        const endpoint = window.location.pathname
        const search = window.location.search
        let days = $(clicked).closest('.input-group').find('input').val()
        days = days !== undefined ? days : 7
        const searchParams = new URLSearchParams(window.location.search)
        searchParams.set('statistics_days', days);
        const url = endpoint + '?' + searchParams
        window.location = url
    }
</script>