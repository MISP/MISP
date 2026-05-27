<?php
    $headerTitle = __('Report #') . ($report['EventReport']['id'] ?? '');
    $headerDescription = '';
    $headerActions = [];

    $this->set('headerTitle', $headerTitle);
    $this->set('headerDescription', $headerDescription);
    $this->set('headerActions', $headerActions);

    echo $this->element('genericElements/assetLoader', [
        'js'  => ['markdown-it'],
        'css' => ['analyst-data'],
    ]);

    echo $this->element('genericElementsBS5/Layout/view_layout',
    [
        'data' => $report,
        'tabs' => [
            [
                'id'    => 'general',
                'title' => __('General'),
                'icon'  => 'info-circle',
                'left'  => [
                    'EventReports/View/eventReport_general',
                    'EventReports/View/eventReport_preview',
                ],
                'right' => [
                    'EventReports/View/eventReport_actions',
                ],
            ],
            [
                'id'    => 'content',
                'title' => __('Edit Content'),
                'icon'  => 'file-lines',
                'left'  => [
                    'EventReports/View/eventReport_content',
                ],
            ],
        ]
    ]);
?>
