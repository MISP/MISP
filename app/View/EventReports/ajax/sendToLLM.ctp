<?php
echo $this->element('genericElements/Form/genericForm', array(
    'form' => $this->Form,
    'data' => array(
        'title' => __('Send report to LLM'),
        'model' => 'EventReport',
        'submit' => array(
            'action' => $this->request->params['action'],
            'ajaxSubmit' => 'confirmSubmissionToLLM()'
        ),
    )
));
?>

<script>
    function confirmSubmissionToLLM() {
        submitGenericFormInPlace(function(data) {
            console.log(data)
        })
    }
</script>