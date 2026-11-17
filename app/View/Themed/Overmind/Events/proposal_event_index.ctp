<?php
/*
 * The events with open proposals, drawn by the events index
 * (Elements/Events/index) over the scope EventsController::proposalEventIndex()
 * gives it, with a Proposals column.
 */
$this->set('headerTitle', __('Events with proposals'));
$this->set('headerDescription', $isSiteAdmin
    ? __('Events with proposals waiting for their creator to accept or discard them.')
    : __('Your organisation\'s events with proposals waiting for you to accept or discard them.'));
$this->set('headerActions', []);
$this->set('headerBreadcrumb', [
    ['label' => __('Events'), 'url' => '/events/index'],
    __('Proposals'),
]);

echo $this->element('Events/index', [
    'events' => $events,
    'show_user_button' => false,
    'show_org_button' => false,
]);
