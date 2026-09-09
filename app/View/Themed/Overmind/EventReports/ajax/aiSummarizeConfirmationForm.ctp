<?php
/*
 * Confirmation of an AI report summary, rendered by
 * EventReportsController::aiSummarize() on GET. The form POSTs back to the
 * same URL; the controller queues the job (or rewrites the report at once
 * when background jobs are off) and redirects to the report with a flash.
 *
 * Set by the controller:
 *   $report  array  the report (EventReport id, name; Event id)
 */
echo $this->element('genericElementsBS5/Modals/confirmation_form', [
    'model' => 'EventReport',
    'url' => $baseurl . '/eventReports/aiSummarize/' . (int)$report['EventReport']['id'],
    'hiddenField' => false,
    'eyebrow' => __('AI actions'),
    'accent' => 'primary',
    'title' => __('Summarise report with AI'),
    'description' => __('The module puts its summary on top of the report. A previous AI summary is replaced.'),
    'message' => __('Send the report "%s" to the AI module and write its summary into it?', $report['EventReport']['name']),
    'warning' => __('The event is unpublished when the report is rewritten. Refresh the page once the job completes.'),
    'submitLabel' => __('Summarise'),
    'submitIcon' => 'robot',
    'icon' => 'fas fa-robot',
    'meta' => [
        ['label' => __('Report'), 'id' => $report['EventReport']['id']],
        ['label' => __('Event'), 'id' => $report['Event']['id']],
    ],
]);
