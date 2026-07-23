<?php
// Overmind BS5 confirm fragment for forceRun. Native submit → the untouched
// forceRun() POST branch saves + redirects to the (themed) index with a Flash.
echo $this->element('genericElementsBS5/Forms/deleteConfirmationForm', [
    'title' => __('Force Run Scheduled Task #%s', h($task['Task']['id'])),
    'model' => 'Task',
    'url' => $baseurl . '/tasks/forceRun/' . h($id),
    'message' => __('Execute the task immediately? This overrides the current scheduled execution time; it can take a few seconds for the scheduler to pick up the task.'),
]);
