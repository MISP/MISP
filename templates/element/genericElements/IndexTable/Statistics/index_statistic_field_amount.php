<?php

use Cake\Utility\Inflector;

$statisticsHtml = '';
$statistics_pie_amount = $this->request->getQuery('statistics_entry_amount', 5);
$statistics_pie_include_remaining = $this->request->getQuery('statistics_include_remainging', true);
if (is_string($statistics_pie_include_remaining)) {
    $statistics_pie_include_remaining = $statistics_pie_include_remaining == 'true' ? true : false;
}
$statistics_pie_ignore_null = $this->request->getQuery('statistics_ignore_null', true);
if (is_string($statistics_pie_ignore_null)) {
    $statistics_pie_ignore_null = $statistics_pie_ignore_null == 'true' ? true : false;
}

$seedPiechart = 's-' . mt_rand();
foreach ($statistics['usage'] as $scope => $graphData) {
    $pieChart = $this->element('charts/pie', [
        'data' => $graphData,
        'chartOptions' => [
            'chart' => [
                'height' => '80px',
                'sparkline' => [
                    'enabled' => true,
                ]
            ],
            'plotOptions' => [
                'pie' => [
                    'customScale' => 0.9,
                ]
            ],
        ],
    ]);
    $titleHtml = sprintf(
        '<span class="text-nowrap">%s%s</span>',
        Inflector::Pluralize(Inflector::Humanize(h($scope))),
        $this->Bootstrap->button([
            'variant' => 'link',
            'icon' => 'cog',
            'size' => 'xs',
            'nodeType' => 'a',
            'onclick' => '',
            'class' => ['btn-statistics-pie-configurator-' . $seedPiechart],
            'attrs' => [
                'data-bs-toggle' => 'popover',
            ]
        ])
    );
    $panelHtml = sprintf(
        '<div class="d-flex flex-row">%s%s</div>',
        $titleHtml,
        $pieChart
    );
    $statPie = $this->Bootstrap->card([
        'bodyHTML' => $panelHtml,
        'bodyClass' => 'py-1 px-2',
        'class' => ['shadow-sm', 'h-100']
    ]);
    $statisticsHtml .= sprintf('<div class="col-sm-6 col-md-5 col-lg-4 col-xl-3 mb-1" style="min-height: 90px;">%s</div>', $statPie);
}
?>

<?= $statisticsHtml ?>

<script>
    $(document).ready(function() {
        let popoverTriggerList = [].slice.call(document.querySelectorAll('.btn-statistics-pie-configurator-<?= $seedPiechart ?>'))
        let popoverList = popoverTriggerList.map(function(popoverTriggerEl) {
            const popover = new bootstrap.Popover(popoverTriggerEl, {
                container: 'body',
                html: true,
                sanitize: false,
                title: () => {
                    return '<div class="d-flex align-items-center justify-content-between"> \
                                <?= __('Configure chart') ?> \
                                <button type = "button" class="btn-xs btn-close" aria-label="Close"></button> \
                            </div>'
                },
                content: () => {
                    return '<div class="popover-form-container"> \
                                <div class="input-group flex-nowrap"> \
                                    <span class="input-group-text"><?= __('Amount') ?></span> \
                                    <input type="number" min="1" class="form-control entry-amount" placeholder="7" aria-label="<?= __('Days') ?>" value="<?= h($statistics_pie_amount) ?>"> \
                                </div> \
                                <div class="form-check"> \
                                    <input class="form-check-input cb-include-remaining" type="checkbox" value="" id="checkbox-include-remaining" <?= $statistics_pie_include_remaining ? 'checked' : '' ?>> \
                                    <label class="form-check-label" for="checkbox-include-remaining"> \
                                        <?= __('Merge skipped entries') ?> \
                                    </label> \
                                </div> \
                                <div class="form-check"> \
                                    <input class="form-check-input cb-ignore-null" type="checkbox" value="" id="checkbox-ignore-null" <?= $statistics_pie_ignore_null ? 'checked' : '' ?>> \
                                    <label class="form-check-label" for="checkbox-ignore-null"> \
                                        <?= __('Ignore NULL values') ?> \
                                    </label> \
                                </div> \
                                <button class="btn btn-primary" type="button" onclick="statisticsPieConfigurationRedirect(this)"><?= __('Update chart') ?> </button> \
                            </div>'
                }
            })
            popoverTriggerEl.addEventListener('shown.bs.popover', function(evt) {
                const popover = bootstrap.Popover.getInstance(this)
                const popoverEl = popover.getTipElement()
                const popoverBtnCloseEl = popoverEl.querySelector('.popover-header button.btn-close')
                popoverBtnCloseEl.addEventListener('click', function() {
                    popover.hide()
                })
            })
            return popover
        })

        let popoverCloseBtnlist = [].slice.call(document.querySelectorAll('.popover .popover-header button.btn-close'))
        popoverCloseBtnlist.map(function(popoverBtnCloseEl) {
            return popoverBtnCloseEl.addEventListener('click', function() {
                const popoverEl = this.closest('.popover')
                const popover = bootstrap.Popover.getInstance(popoverEl)
                if (popover !== null) {
                    popover.hide()
                }
            })
        })
    })

    function statisticsPieConfigurationRedirect(clicked) {
        const endpoint = window.location.pathname
        const search = window.location.search
        let entryAmount = $(clicked).closest('.popover-form-container').find('input.entry-amount').val()
        let includeRemaining = $(clicked).closest('.popover-form-container').find('input.cb-include-remaining').prop('checked')
        let ignoreNull = $(clicked).closest('.popover-form-container').find('input.cb-ignore-null').prop('checked')
        entryAmount = entryAmount !== undefined ? entryAmount : 5
        includeRemaining = includeRemaining !== undefined ? includeRemaining : true
        ignoreNull = ignoreNull !== undefined ? ignoreNull : true
        const searchParams = new URLSearchParams(window.location.search)
        searchParams.set('statistics_entry_amount', entryAmount);
        searchParams.set('statistics_include_remainging', includeRemaining);
        searchParams.set('statistics_ignore_null', ignoreNull);
        const url = endpoint + '?' + searchParams
        window.location = url
    }
</script>