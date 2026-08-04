<?php
    $headerTitle = __('Report #') . ($report['EventReport']['id'] ?? '');
    $headerDescription = '';
    $headerActions = [];

    $this->set('headerTitle', $headerTitle);
    $this->set('headerDescription', $headerDescription);
    $this->set('headerActions', $headerActions);

    echo $this->element('genericElements/assetLoader', [
        'js'  => ['markdown-it']
    ]);

    echo $this->element('genericElementsBS5/Layout/view_layout',
    [
        'data' => $report,
        'tabs' => [
            [
                'id'    => 'general',
                'title' => __('General'),
                'icon'  => 'fas fa-info-circle',
                'left'  => [
                    'EventReports/View/eventReport_general',
                    'EventReports/View/eventReport_preview',
                ],
                'right' => [
                    'EventReports/View/eventReport_actions',
                    'EventReports/View/eventReport_analyst_data',
                ],
            ],
            [
                'id'    => 'content',
                'title' => __('Edit Content'),
                'icon'  => 'fas fa-file-lines',
                'left'  => [
                    'EventReports/View/eventReport_content',
                ],
            ],
        ]
    ]);
?>
