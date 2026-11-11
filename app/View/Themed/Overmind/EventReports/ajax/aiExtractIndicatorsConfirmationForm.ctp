<?php
/*
 * Confirmation of an AI indicator extraction from one report (A4, report
 * scope), rendered by EventReportsController::aiExtractIndicators() on GET
 * into the main modal. The submit posts the form by fetch; the controller
 * queries the module with this report only while the modal shows a spinner
 * and answers the review screen, which replaces this content. Nothing is
 * saved before that screen is submitted.
 *
 * Set by the controller:
 *   $report         array   the report (EventReport id, name, uuid; Event id)
 *   $minConfidence  mixed   Plugin.AI_min_confidence
 *   $timeout        int     Plugin.AI_timeout, seconds
 */
$threshold = ($minConfidence === null || $minConfidence === '') ? '0.9' : $minConfidence;
echo $this->element('genericElementsBS5/Modals/confirmation_form', [
    'model' => 'EventReport',
    'url' => $baseurl . '/eventReports/aiExtractIndicators/' . (int)$report['EventReport']['id'],
    'hiddenField' => false,
    'eyebrow' => __('AI actions'),
    'accent' => 'primary',
    'title' => __('Extract indicators with AI'),
    'description' => __('The module reads this report and proposes attributes and objects for the event.'),
    'message' => __('The AI module reads the report "%s" and lists the indicators it finds with a confidence of %s or higher, each tagged ai-computer-assisted; the event\'s other reports are not sent. You review the list and remove anything wrong before it is added.', $report['EventReport']['name'], $threshold),
    'warning' => __('The duration of the task is variable based on the model used and server utilisation, at most %s s; the event is unpublished when you import.', (int)$timeout),
    'submitLabel' => __('Extract'),
    'submitIcon' => 'magnifying-glass',
    'icon' => 'fas fa-robot',
    'meta' => [
        ['label' => __('Report'), 'id' => $report['EventReport']['id']],
        ['label' => __('Event'), 'id' => $report['Event']['id']],
    ],
]);
echo $this->element('genericElementsBS5/Modals/ai_extract_submit_script');
