<?php
    $data = array(
        'title' => __('Event report: %s', h($report['EventReport']['name'])),
        'content' => array(
            array(
                'html' => $this->element('EventReports/markdownEditor', array(
                    'canEdit' => $canEdit,
                    'insideModal' => true,
                    'markdown' => $report['EventReport']['content'],
                    'proxyMISPElements' => $proxyMISPElements,
                    'modelName' => 'EventReport',
                    'mardownModelFieldName' => 'content',
                    'eventid' => $report['EventReport']['event_id'],
                    'reportid' => $report['EventReport']['id'],
                    'webDependencies' => array('js' => array('markdownEditor/event-report'), 'css' => array('event-report')),
                    'helpModal' => 'EventReports/markdownEditorHelpModal'
                ))
            ),
        )
    );
    echo $this->element('genericElements/infoModal', array('data' => $data, 'type' => 'xl'));
?>
