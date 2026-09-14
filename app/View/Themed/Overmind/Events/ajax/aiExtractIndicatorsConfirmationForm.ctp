<?php
/*
 * Confirmation of an AI indicator extraction (A4), rendered by
 * EventsController::aiExtractIndicators() on GET into the main modal. The
 * submit POSTs the form by fetch; the controller queries the module while
 * the modal shows a spinner and answers the review screen (the same modal
 * body enrichment results use), which replaces this content. Nothing is
 * saved before that screen is submitted.
 *
 * Set by the controller:
 *   $event          array   the event (id, info)
 *   $reports        int     non-deleted reports on the event
 *   $minConfidence  mixed   Plugin.AI_min_confidence
 *   $timeout        int     Plugin.AI_timeout, seconds
 */
$eventId = (int)$event['Event']['id'];
$threshold = ($minConfidence === null || $minConfidence === '') ? '0.9' : $minConfidence;
$message = __n(
    'The AI module reads the %s report of this event and lists the indicators it finds with a confidence of %s or higher, each tagged ai-computer-assisted. You review the list and remove anything wrong before it is added.',
    'The AI module reads the %s reports of this event and lists the indicators it finds with a confidence of %s or higher, each tagged ai-computer-assisted. You review the list and remove anything wrong before it is added.',
    (int)$reports,
    (int)$reports,
    h($threshold)
);
$warning = __('The module usually answers within a minute, at most %s s; the event is unpublished when you import.', (int)$timeout);
if ((int)$reports === 0) {
    $warning = __('This event has no report: nothing can be extracted.');
}
echo $this->element('genericElementsBS5/Modals/confirmation_form', [
    'model' => 'Event',
    'url' => $baseurl . '/events/aiExtractIndicators/' . $eventId,
    'hiddenField' => false,
    'eyebrow' => __('AI actions'),
    'accent' => 'primary',
    'title' => __('Extract indicators with AI'),
    'description' => __('The module reads the event reports and proposes attributes and objects.'),
    'message' => $message,
    'warning' => $warning,
    'submitLabel' => __('Extract'),
    'submitIcon' => 'magnifying-glass',
    'icon' => 'fas fa-robot',
    'meta' => [['label' => __('Event'), 'id' => $eventId]],
    'canProceed' => (int)$reports > 0,
]);
echo $this->element('genericElementsBS5/Modals/ai_extract_submit_script');
