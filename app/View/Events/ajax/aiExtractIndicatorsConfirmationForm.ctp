<?php
/*
 * Confirmation of an AI indicator extraction (A4), rendered by
 * EventsController::aiExtractIndicators() on GET and opened with
 * openGenericModal(). A native POST: the controller queries the module
 * while the browser waits, then renders the review screen import modules
 * use. Nothing is saved before that screen is submitted.
 *
 * Set by the controller:
 *   $event          array   the event (id, info)
 *   $reports        int     non-deleted reports on the event
 *   $minConfidence  mixed   Plugin.AI_min_confidence
 *   $timeout        int     Plugin.AI_timeout, seconds
 */
$eventId = (int)$event['Event']['id'];
$description = __n(
    'The AI module reads the %s report of event #%s and lists the indicators it finds with a confidence of %s or higher, each tagged ai-computer-assisted.',
    'The AI module reads the %s reports of event #%s and lists the indicators it finds with a confidence of %s or higher, each tagged ai-computer-assisted.',
    (int)$reports,
    (int)$reports,
    h($eventId),
    h($minConfidence === null || $minConfidence === '' ? '0.9' : $minConfidence)
);
$description .= ' ' . __('You review the list and untick anything wrong before it is added; the event is unpublished when you import.');
$description .= ' ' . __('The duration of the task is variable based on the model used and server utilisation, at most %s s.', (int)$timeout);
if ((int)$reports === 0) {
    $description .= ' ' . __('This event has no report: nothing can be extracted.');
}
echo $this->element('genericElements/Form/genericForm', array(
    'form' => $this->Form,
    'data' => array(
        'title' => __('Extract indicators with AI'),
        'description' => $description,
        'model' => 'Event',
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
        <?php if ((int)$reports === 0): ?>
        return false;
        <?php endif; ?>
    });
</script>
