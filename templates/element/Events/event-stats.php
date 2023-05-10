<?php
$eventid = 2;
$warningslist_hits = $warningslist_hits;
$recent_sightings = [
    [(time() - 8 * 86400) * 1000, 1], [(time() - 7 * 86400) * 1000, 2], [(time() - 3 * 86400) * 1000, 1],
];
$stat_distribution = array_map(function ($e) use ($stats) {
    return ceil(100 * $e / $stats['stat_counts']['attributes']);
}, array_filter($stats['stat_distribution']));
?>

<div class="stat-container container-fluid ps-0 pe-0">
    <div class="row g-2">
        <div class="stat-panel-md">
            <?php
            $chartActivityHtml = $this->element('charts/generic', [
                'series' => [
                    ['data' => [12, 14, 2, 15, 47, 75, 65, 19, 14]]
                ],
                'chartOptions' => [
                    'chart' => [
                        'type' => 'bar',
                        'height' => '160',
                        'toolbar' => [
                            'show' => false,
                        ],
                        'zoom' => [
                            'enabled' => false,
                        ],
                    ],
                    'stroke' => [
                        'curve' => 'straight'
                    ],
                    'title' => [
                        'text' => __('Event activity'),
                    ],
                    'labels' => [
                        (time() - 8 * 86400) * 1000, (time() - 7 * 86400) * 1000, (time() - 6 * 86400) * 1000, (time() - 5 * 86400) * 1000, (time() - 4 * 86400) * 1000, (time() - 3 * 86400) * 1000, (time() - 2 * 86400) * 1000, (time() - 1 * 86400) * 1000, time() * 1000
                    ],
                    'grid' => [
                        'show' => true,
                        'yaxis' => [
                            'lines' => [
                                'show' => true,
                            ],
                        ],
                    ],
                    'yaxis' => [
                        'show' => false,
                    ],
                    'xaxis' => [
                        'type' => 'datetime',
                    ],
                    'dataLabels' => [
                        'enabled' => false,
                    ],
                    'tooltip' => [
                        'enabled' => false,
                        'x' => [
                            'show' => false,
                        ],
                        'marker' => [
                            'show' => false,
                        ]
                    ],
                    'annotations' => [
                        'xaxis' => [
                            [
                                'x' => (time() - 3 * 86400) * 1000,
                                'strokeDashArray' => 0,
                                'borderColor' => '#ff0000',
                                'label' => [
                                    'style' => [
                                        'color' => '#fff',
                                        'background' => "#ff0000"
                                    ],
                                    'text' => __('Published')
                                ],
                            ],
                        ]
                    ]
                ],
            ]);
            echo $this->Bootstrap->card([
                'bodyHTML' => $chartActivityHtml,
                'bodyClass' => ['p-0'],
                'class' => ['h-100'],
            ]);
            ?>
        </div>
        <div class="stat-panel-md2">
            <?php
            $countsHtml = $this->Bootstrap->render(
                '<table class="table align-middle table-borderless mb-0">
                    <tbody>
                        <tr>
                            <td><span class="fw-bold fs-4">{{proposal_count}}</span> <span class="text-uppercase fw-light fs-7">{{proposal_text}}</span></td>
                            <td><span class="fw-bold fs-4">{{sighting_count}}</span> <span class="text-uppercase fw-light fs-7">{{sighting_text}}</span></td>
                        </tr>
                        <tr>
                            <td><span class="fw-bold fs-4">{{extension_count}}</span> <span class="text-uppercase fw-light fs-7">{{extension_text}}</span></td>
                            <td><span class="fw-bold fs-4">{{deleted_count}}</span> <span class="text-uppercase fw-light fs-7">{{deleted_text}}</span></td>
                        </tr>
                        <tr>
                            <td><span class="fw-bold fs-4">{{feedhit_count}}</span> <span class="text-uppercase fw-light fs-7">{{feedhit_text}}</span></td>
                            <td><span class="fw-bold fs-4 {{warninglist_class}}">{{warninglist_count}}</span> <span class="text-uppercase fw-light fs-7">{{warninglist_text}}</span></td>
                        </tr>
                        <tr>
                            <td><span class="fw-bold fs-4">{{relationship_count}}</span> <span class="text-uppercase fw-light fs-7">{{relationship_text}}</span></td>
                            <td><span class="fw-bold fs-4">{{iocs_count}}</span><span class="fw-light fs-8" title="{{iocs_percentage_title}}">{{iocs_percentage}}</span> <span class="text-uppercase fw-light fs-7">{{ioc_text}}</span></td>
                        </tr>
                    </tbody>
                </table>',
                [
                    'proposal_text' => __('Proposals'),
                    'deleted_text' => __('Deleted'),
                    'eventreport_text' => __('Event Reports'),
                    'relationship_text' => __('Relationships'),
                    'correlation_text' => __('Correlations'),
                    'sighting_text' => __('Sightings'),
                    'extension_text' => __('Extensions'),
                    'ioc_text' => __('IoCs'),
                    'iocs_percentage_title' => __('Percentage of IoCs compared to total amount of attributes'),
                    'feedhit_text' => __('Feed hits'),
                    'warninglist_text' => __('Warninglist hits'),
                    'placeholder2_text' => 'text2',
                    'proposal_count' => $stats['stat_counts']['proposals'],
                    'deleted_count' => $stats['stat_counts']['attribute_deleted'],
                    'eventreport_count' => $stats['stat_counts']['eventreports'],
                    'relationship_count' => $stats['stat_counts']['relationships'],
                    'correlation_count' => $stats['stat_counts']['correlations'],
                    'sighting_count' => $stats['stat_counts']['sightings'],
                    'extension_count' => $stats['stat_counts']['extensions'],
                    'iocs_count' => $stats['stat_counts']['iocs'],
                    'iocs_percentage' => sprintf('%s%%', round(100 * $stats['stat_counts']['iocs'] / $stats['stat_counts']['attributes'])),
                    'feedhit_count' => $stats['stat_counts']['feed_correlations'],
                    'warninglist_count' => count($warningslist_hits),
                    'warninglist_class' => count($warningslist_hits) > 0 ? 'text-danger' : 'text-body',
                ]
            );
            echo $this->Bootstrap->card([
                'bodyHTML' => $countsHtml,
                'bodyClass' => ['d-flex align-items-center py-1'],
                'class' => ['h-100'],
            ]);
            ?>
        </div>
        <div class="stat-panel-sm chart-distribution-container">
            <?php
            echo $this->Bootstrap->card([
                'bodyHTML' => $this->element('charts/generic', [
                    'series' => $stat_distribution,
                    'chartOptions' => [
                        'labels' => $stats['distribution_levels'],
                        'chart' => [
                            'type' => 'radialBar',
                            'height' => 190,
                        ],
                        'plotOptions' => [
                            'radialBar' => [
                                'dataLabels' => [
                                    'total' => [
                                        'label' => 'Distribution',
                                        'show' => true,
                                        'fontSize' => 'var(--bs-body-font-size)',
                                        'formatter' => 'totalDistributionFormatter',
                                    ]
                                ]
                            ]
                        ],
                    ],
                ]),
                'bodyClass' => ['p-0', 'd-flex flex-wrap align-items-center'],
                'class' => ['h-100'],
            ]);
            ?>
        </div>
        <div class="stat-panel-sm">
            <?php
            $chartOptionsCommon = [
                'chart' => [
                    'type' => 'donut',
                    'height' => 160,
                    'offsetY' => 6,
                ],
                'dataLabels' => [
                    'enabled' => false
                ],
                'legend' => [
                    'show' => false,
                ],
                'plotOptions' => [
                    'pie' => [
                        'donut' => [
                            'size' => '70%',
                            'labels' => [
                                'show' => true,
                                'value' => [
                                    'offsetY' => 0,
                                ],
                                'total' => [
                                    'show' => true,
                                    // 'showAlways' => true,
                                    'label' => __('??'),
                                    'fontSize' => 'var(--bs-body-font-size)',
                                    'formatter' => 'alert(1)',
                                ]
                            ]
                        ]
                    ]
                ],
            ];
            $chartOptionsObjects = $chartOptionsCommon;
            $chartOptionsObjects['plotOptions']['pie']['donut']['labels']['total']['label'] = __('Objects');
            $chartOptionsObjects['plotOptions']['pie']['donut']['labels']['total']['formatter'] = 'totalObjectFormatter';
            echo $this->Bootstrap->card([
                'bodyHTML' => $this->element('charts/pie', [
                    'data' => $stats['stat_objects_6'],
                    'chartOptions' => $chartOptionsObjects,
                ]),
                'bodyClass' => ['p-0', 'd-flex flex-wrap align-items-center'],
                'class' => ['h-100'],
            ]);
            ?>
        </div>
        <div class="stat-panel-sm">
            <?php
            $chartOptionsAttributes = $chartOptionsCommon;
            $chartOptionsAttributes['plotOptions']['pie']['donut']['labels']['total']['label'] = __('Attributes');
            $chartOptionsAttributes['plotOptions']['pie']['donut']['labels']['total']['formatter'] = 'totalAttributeFormatter';
            echo $this->Bootstrap->card([
                'bodyHTML' => $this->element('charts/pie', [
                    'data' => $stats['stat_attributes_6'],
                    'chartOptions' => $chartOptionsAttributes
                ]),
                'bodyClass' => ['p-0', 'd-flex flex-wrap align-items-center'],
                'class' => ['h-100'],
            ]);
            ?>
        </div>
        <div class="stat-panel-md">
            <?php
            $chartSightingsHtml = $this->element('charts/generic', [
                'series' => [
                    ['data' => array_map(function ($entry) {
                        return $entry[1];
                    }, $recent_sightings)]
                ],
                'chartOptions' => [
                    'chart' => [
                        'type' => 'bar',
                        'height' => '160',
                        'toolbar' => [
                            'show' => false,
                        ],
                        'zoom' => [
                            'enabled' => false,
                        ],
                    ],
                    'stroke' => [
                        'curve' => 'straight'
                    ],
                    'title' => [
                        'text' => __('Recent sightings'),
                    ],
                    'labels' => array_map(function ($entry) {
                        return $entry[0];
                    }, $recent_sightings),
                    'grid' => [
                        'show' => true,
                        'yaxis' => [
                            'lines' => [
                                'show' => true,
                            ],
                        ],
                    ],
                    'yaxis' => [
                        'show' => false,
                    ],
                    'xaxis' => [
                        'type' => 'datetime',
                    ],
                    'dataLabels' => [
                        'enabled' => true,
                    ],
                    'tooltip' => [
                        'enabled' => false,
                        'x' => [
                            'show' => false,
                        ],
                        'marker' => [
                            'show' => false,
                        ]
                    ],
                ],
            ]);
            echo $this->Bootstrap->card([
                'bodyHTML' => $chartSightingsHtml,
                'bodyClass' => ['p-0'],
                'class' => ['h-100'],
            ]);
            ?>
        </div>

        <div class="stat-panel-md">
            <?php
            $tmpHtml = '<strong>Relevant correlations go here</strong>';
            $tmpHtml .= '<ul class="mt-2">';
            $tmpHtml .= '    <li>Events with some context overlap</li>';
            $tmpHtml .= '    <li>Events created by other orgs</li>';
            $tmpHtml .= '    <li>...</li>';
            $tmpHtml .= '</ul>';
            echo $this->Bootstrap->card([
                'bodyHTML' => $tmpHtml,
                'bodyClass' => ['pt-1'],
                'class' => ['h-100'],
            ]);
            ?>
        </div>
    </div>
</div>

<script>
    const url = "<?= $baseurl ?>/events/getStatistics/<?= $eventid ?>"

    function totalObjectFormatter(w) {
        return '<?= $stats['stat_counts']['objects'] ?>'
    }

    function totalAttributeFormatter(w) {
        return '<?= $stats['stat_counts']['attributes'] ?>'
    }

    function totalDistributionFormatter(w) {
        return ''
    }
</script>

<style>
    .stat-container .row>.col-2 {
        /* min-width: 270px;
        max-width: 320px; */
    }

    .stat-container .row>div.stat-panel-sm {
        height: 160px;
        width: 160px;
    }

    .stat-container .row>div.stat-panel-md {
        height: 160px;
        width: 280px;
    }

    .stat-container .row>div.stat-panel-md2 {
        height: 160px;
        width: 300px;
    }

    .stat-container .row>div.stat-panel-lg {
        height: 160px;
        width: 400px;
    }

    .stat-container .apexcharts-datalabels-group .apexcharts-datalabel-label {
        padding: 0 5px;
        white-space: nowrap;
        paint-order: stroke;
        stroke: var(--bs-card-bg);
        stroke-width: 2px;
    }

    .apexcharts-svg text {
        fill: var(--bs-body-color);
    }
</style>