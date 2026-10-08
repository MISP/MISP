<?php
/*
 * Confirmation of an AI indicator extraction from one report (A4, report
 * scope), rendered by EventReportsController::aiExtractIndicators() on GET
 * and opened with openGenericModal(). A native POST: the controller queries
 * the module with this report only while the browser waits, then renders
 * the review screen import modules use. Nothing is saved before that screen
 * is submitted.
 *
 * Set by the controller:
 *   $report         array   the report (EventReport id, name, uuid; Event id)
 *   $minConfidence  mixed   Plugin.AI_min_confidence
 *   $timeout        int     Plugin.AI_timeout, seconds
 */
$threshold = ($minConfidence === null || $minConfidence === '') ? '0.9' : $minConfidence;
$description = __('The AI module reads the report "%s" (#%s) and lists the indicators it finds with a confidence of %s or higher, each tagged ai-computer-assisted; the event\'s other reports are not sent.', h($report['EventReport']['name']), h($report['EventReport']['id']), h($threshold));
$description .= ' ' . __('You review the list and untick anything wrong before it is added to event #%s; the event is unpublished when you import.', h($report['Event']['id']));
$description .= ' ' . __('The duration of the task is variable based on the model used and server utilisation, at most %s s.', (int)$timeout);
echo $this->element('genericElements/Form/genericForm', array(
    'form' => $this->Form,
    'data' => array(
        'title' => __('Extract indicators with AI'),
        'description' => $description,
        'model' => 'EventReport',
        'submit' => array(
            'action' => $this->request->params['action'],
        ),
    )
));
?>
<script type="text/javascript">
    // A native submit: the browser waits for the module and lands on the
    // review page. Show that it is waiting.
    $('.genericForm').on('submit', function () {
        $('#submitButton').prop('disabled', true).html('<i class="fas fa-spinner fa-spin"></i> <?= __('Waiting for the module…') ?>');
    });
</script>
