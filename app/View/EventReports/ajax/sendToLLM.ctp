<?php
echo $this->element('genericElements/Form/genericForm', array(
    'form' => $this->Form,
    'data' => array(
        'title' => __('Send report to LLM'),
        'model' => 'EventReport',
        'submit' => array(
            'action' => $this->request->params['action'],
            'ajaxSubmit' => 'confirmSubmissionToLLM(this)'
        ),
    )
));
?>

<script>
    function confirmSubmissionToLLM(clicked) {
        $clicked = $(clicked)
        $loading = $('<div style="display:flex; align-items: center; flex-direction: column;"></div>').append(
            $('<h3>Waiting for the robot to do its magic...</h3>'),
            $('</br>'),
            $('<i class="fas fa-robot fa-5x fa-spin"></i>'),
            $('</br>'),
        )
        $clicked.parent().parent().find('.modal-body').append($loading)
        submitGenericFormInPlace(function(data) {
            window.location.reload();
        });
    }
</script>