<?php
/*
 * Confirmation of an AI event summary, rendered by
 * EventsController::aiSummarize() on GET and opened with openGenericModal().
 * The generic form POSTs back to /events/aiSummarize/<id> over AJAX; the
 * controller queues the job (or adds the report at once when background jobs
 * are off) and answers JSON, after which the event is reloaded.
 *
 * Set by the controller:
 *   $event  array  the event (id, info)
 */
echo $this->element('genericElements/Form/genericForm', array(
    'form' => $this->Form,
    'data' => array(
        'title' => __('Summarise event with AI'),
        'description' => __('Event #%s is sent to the AI module, which writes its summary into a new event report. The report is attached when the module answers and the event is unpublished; refresh the event to see it.', h($event['Event']['id'])),
        'model' => 'Event',
        'submit' => array(
            'action' => $this->request->params['action'],
            'ajaxSubmit' => 'submitAiSummarize()'
        ),
    )
));
?>
<script type="text/javascript">
    function submitAiSummarize() {
        var $button = $('#submitButton');
        $button.prop('disabled', true);
        submitGenericFormInPlace(function (data) {
            if (data && data.saved === false) {
                $button.prop('disabled', false);
                showMessage('fail', typeof data.errors === 'string' ? data.errors : (data.message || '<?= __('The AI summary could not be requested.') ?>'));
                return;
            }
            showMessage('success', (data && data.success) || '<?= __('AI summary requested.') ?>');
            window.location.reload();
        });
    }
</script>
