<?php
    $data = array(
        'title' => __('Event report: %s', h($report['EventReport']['name'])),
        'content' => array(
            array(
                'html' => $this->element('EventReports/markdownViewer', array(
                    'markdown' => $report['EventReport']['content'],
                    'proxyMISPElements' => $proxyMISPElements,
                    'modelName' => 'EventReport',
                    'mardownModelFieldName' => 'content',
                ))
            ),
        )
    );
    echo $this->element('genericElements/infoModal', array('data' => $data, 'type' => 'xl'));
?>
