<?php

$objectHtml = '<i>objects</i>';
$attributeHtml = '<b>attributes</b>';
$reporttHtml = 'reports';
$eventGraphHtml = 'eventgraph';
$timelineHtml = 'timeline';
$attackHtml = 'Include matrix, preventive measures & mitigations ';
$discussionHtml = 'discussion';

echo $this->Bootstrap->tabs([
   'horizontal-position' => 'top',
    'fill-header' => true,
    'card' => true,
    'data' => [
        'navs' => [
            [
                'html' => sprintf(
                    '%s %s',
                    $this->Bootstrap->icon($iconToTableMapping['Objects']),
                    __('Objects') . $this->Bootstrap->badge(['text' => $stats['stat_counts']['objects'],
                        'variant' => 'primary',
                    ])
                ),
                'active' => true,
            ],
            [
                'html' => sprintf(
                    '%s %s',
                    $this->Bootstrap->icon($iconToTableMapping['Attributes']),
                    __('Attributes') . $this->Bootstrap->badge(['text' => $stats['stat_counts']['attributes'],
                        'variant' => 'primary',
                    ])
                ),
            ],
            [
                'html' => sprintf(
                    '%s %s',
                    $this->Bootstrap->icon($iconToTableMapping['EventReports']),
                    __('Reports') . $this->Bootstrap->badge(['text' => $stats['stat_counts']['eventreports'],
                        'variant' => $stats['stat_counts']['eventreports'] > 0 ? 'warning' : 'primary',
                    ])
                ),
            ],
            ['html' => sprintf('%s %s', $this->Bootstrap->icon('diagram-project'), __('Event Graph')),],
            ['html' => sprintf('%s %s', $this->Bootstrap->icon('timeline'), __('Event Timeline')),],
            [
                'html' => $this->Bootstrap->node('span', [
                    'class' => ['text-uppercase'],
                    'style' => 'color: #C8452B;'
                ], 'ATT&CK' . '<sup>®</sup>'),
            ],
            [
                'html' => sprintf(
                    '%s %s',
                    $this->Bootstrap->icon('comments'),
                    __('Discussion') . $this->Bootstrap->badge(['text' => $stats['stat_counts']['discussions'],
                        'variant' => $stats['stat_counts']['discussions'] > 0 ? 'warning' : 'primary',
                    ])
                ),
            ],
        ],
        'content' => [
            $objectHtml,
            $attributeHtml,
            $reporttHtml,
            $eventGraphHtml,
            $timelineHtml,
            $attackHtml,
            $discussionHtml,
        ]
    ]
]);
