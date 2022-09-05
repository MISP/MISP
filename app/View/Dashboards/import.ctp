<?php
    echo $this->element('genericElements/Form/genericForm', array(
        'form' => $this->Form,
        'url' => 'updateSettings',
        'data' => array(
            'title' => __('Import Dashboard Configuration'),
            'model' => 'Dashboard',
            'fields' => array(
                array(
                    'field'=> 'value',
                    'type' => 'textarea',
                    'class' => 'input span6',
                    'div' => 'input clear',
                    'label' => __('Config'),
                    'default' => empty($data['config']) ? '' : json_encode($data['config'], JSON_PRETTY_PRINT)
                )
            ),
            'submit' => array(
                'action' => 'import',
                'ajaxSubmit' => "submitImportDashboardForm()"
            ),
            'description' => __('Import a configuration JSON as exported from another MISP instance.')
        )
    ));
?>
<script>
function submitImportDashboardForm() {
    var $form = $('#DashboardImportForm')
    var json = $form.find('textarea[name="data[Dashboard][value]"]').val()
    try {
        json = JSON.parse(json)
        $form.submit()
    } catch (error) {
        showMessage('fail', error.message)
    }
}
</script>
