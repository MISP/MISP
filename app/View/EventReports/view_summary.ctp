<?php
    $data = array(
        'title' => __('Event report: %s', h($report['EventReport']['name'])),
        'content' => array(
            array(
                'html' => $this->element('markdownEditor/markdownEditor', [
                    'insideModal' => true,
                    'canEdit' => $canEdit,
                    'markdown' => $report['EventReport']['content'],
                    'modelName' => 'EventReport',
                    'mardownModelFieldName' => 'content',
                    'lastModified' => $report['EventReport']['timestamp'],
                    'additionalMarkdownElements' => [
                        'path' => 'EventReports/reportEditor',
                        'variables' => [
                            'reportid' => $report['EventReport']['id'],
                            'eventid' => $report['EventReport']['event_id'],
                        ]
                    ],
                    'additionalMarkdownHelpModalElements' => [[
                        'path' => 'EventReports/reportHelpModal',
                        'tab_name' => __('Markdown format'),
                    ]],
                    'editRedirect' => sprintf('%s/eventReports/view/%s', $baseurl, $report['EventReport']['id']),
                ])
            ),
        )
    );
    echo $this->element('genericElements/infoModal', array('data' => $data, 'type' => 'xl'));
?>
