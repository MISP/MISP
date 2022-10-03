<?php
echo $this->element('genericElements/Form/genericForm', [
    'form' => $this->Form,
    'data' => [
        'title' => __('Export the selected events into the selected format'),
        'model' => 'Event',
        'fields' => [
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
        var idListStr = '<?= json_encode($idList) ?>'
        var returnFormat = $('#EventReturnFormat').val()
        window.location = '<?= $baseurl ?>/events/restSearchExport/' + idListStr + '/' + returnFormat
    }
</script>
