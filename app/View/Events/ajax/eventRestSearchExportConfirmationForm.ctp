<?php
echo $this->element('genericElements/Form/genericForm', [
    'form' => $this->Form,
    'formOptions' => ['url' => ['controller' => 'events', 'action' => 'restSearchExport'], 'type' => 'post'],
    'data' => [
        'title' => __('Export the selected events into the selected format'),
        'model' => 'Event',
        'fields' => [
            ['field' => 'eventid', 'type' => 'hidden', 'default' => json_encode($idList)],
            [
                'field' => 'returnFormat',
                'label' => __('Export Format'),
                'class' => 'input span6',
                'div' => 'input clear',
                'type' => 'select',
                'options' => $exportFormats,
            ],
        ],
        'submit' => [
            'action' => $this->request->params['action'],
            'ajaxSubmit' => 'redirectToExportResult()'
        ],
    ],
]);
?>
<script>
    function redirectToExportResult() {
        // Native POST keeps large ID sets out of URL/request-line limits.
        $('#EventReturnFormat').closest('form')[0].submit();
    }
</script>
