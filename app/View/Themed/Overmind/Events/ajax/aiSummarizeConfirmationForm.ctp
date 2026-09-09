<?php
/*
 * Confirmation of an AI event summary, rendered by
 * EventsController::aiSummarize() on GET. The form POSTs back to the same
 * URL; the controller queues the job (or adds the report at once when
 * background jobs are off) and redirects to the event with a flash.
 *
 * Set by the controller:
 *   $event  array  the event (id, info)
 */
echo $this->element('genericElementsBS5/Modals/confirmation_form', [
    'model' => 'Event',
    'url' => $baseurl . '/events/aiSummarize/' . (int)$event['Event']['id'],
    'hiddenField' => false,
    'eyebrow' => __('AI actions'),
    'accent' => 'primary',
    'title' => __('Summarise event with AI'),
    'description' => __('The module writes its summary into a new event report.'),
    'message' => __('Send this event to the AI module and attach its summary as a new report?'),
    'warning' => __('The event is unpublished when the report is added. Refresh the event once the job completes.'),
    'submitLabel' => __('Summarise'),
    'submitIcon' => 'robot',
    'icon' => 'fas fa-robot',
    'meta' => [['label' => __('Event'), 'id' => $event['Event']['id']]],
]);
