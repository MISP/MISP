<?php
    $railCards = $railCards ?? [];
    $this->set('headerIdentity', $report['EventReport']);
    $this->set('headerTimestamps', $report['EventReport']);
    $headerTitle = $report['EventReport']['name'] ?? '';
    $headerDescription = '';
    $headerActions = [];

    $this->set('headerTitle', $headerTitle);
    $this->set('headerDescription', $headerDescription);
    $this->set('headerActions', $headerActions);

    echo $this->element('genericElements/assetLoader', [
        'js'  => ['markdown-it', 'font-awesome-helper', 'misp-report-markdown']
    ]);

    echo $this->element('genericElementsBS5/Layout/view_layout',
    [
        'data' => $report,
        'ownership' => [
            'orgc' => $report['Event']['Orgc'] ?? [],
            'org' => $report['Event']['Org'] ?? [],
            'distribution' => $report['EventReport']['distribution'] ?? null,
            'sharingGroup' => $report['SharingGroup'] ?? [],
            'inherited' => empty($parentEvent) ? [] : [
                'distribution' => $parentEvent['Event']['distribution'],
                'sharingGroup' => $parentEvent['SharingGroup'] ?? [],
                'label' => __('Inherited from event #%s', $parentEvent['Event']['id']),
                'url' => $baseurl . '/events/view/' . $parentEvent['Event']['id'],
            ],
        ],
        'tabs' => [
            [
                'id'    => 'general',
                'title' => __('General'),
                'icon'  => 'fas fa-info-circle',
                'left'  => [
                    'EventReports/View/eventReport_general',
                    'EventReports/View/eventReport_preview',
                ],
                'right' => array_merge([
                    'EventReports/View/eventReport_actions',
                    'EventReports/View/eventReport_analyst_data',
                ], $this->RailCard->rail($railCards, [
                    'report-siblings', 'report-mentions',
                ], 'general')),
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
