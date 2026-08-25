<?php
// Overmind BS5 confirm fragment for toggleEnabled. $enabled is the TARGET state
// (the controller sets it to !$task.enabled). Native submit → the Overmind
// branch of toggleEnabled() POST saves + redirects to the (themed) index.
echo $this->element('genericElementsBS5/Forms/deleteConfirmationForm', [
    'title' => $enabled
        ? __('Enable Scheduled Task #%s', h($id))
        : __('Disable Scheduled Task #%s', h($id)),
    'model' => 'Task',
    'url' => $baseurl . '/tasks/toggleEnabled/' . h($id),
    'message' => $enabled
        ? __('Are you sure you want to enable scheduled task #%s?', h($id))
        : __('Are you sure you want to disable scheduled task #%s?', h($id)),
]);
