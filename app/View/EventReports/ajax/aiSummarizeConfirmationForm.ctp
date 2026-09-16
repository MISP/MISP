<?php
/*
 * Confirmation of an AI report summary, rendered by
 * EventReportsController::aiSummarize() on GET and opened with
 * openGenericModal(). The generic form POSTs back to
 * /eventReports/aiSummarize/<id> over AJAX; the controller queues the job
 * (or rewrites the report at once when background jobs are off) and
 * answers JSON, after which the page is reloaded.
 *
 * Set by the controller:
 *   $report  array  the report (EventReport id, name; Event id)
 */
echo $this->element('genericElements/Form/genericForm', array(
    'form' => $this->Form,
    'data' => array(
        'title' => __('Summarise report with AI'),
        'description' => __('Report #%s "%s" is sent to the AI module, which puts its summary on top of the report. A previous AI summary is replaced. The report is rewritten when the module answers and the event is unpublished; refresh the page to see it.', h($report['EventReport']['id']), h($report['EventReport']['name'])),
        'model' => 'EventReport',
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
