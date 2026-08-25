<?php
$eventIds = $eventIds ?? [];
$count = count($eventIds);
$serverName = !empty($server['Server']['name'])
    ? $server['Server']['name']
    : ($server['Server']['url'] ?? '');

$message = $count === 1
    ? __('Fetch and save event #%s from "%s" on your instance?', $eventIds[0], $serverName)
    : __('Fetch and save %s events from "%s" on your instance?', $count, $serverName);

echo $this->element('genericElementsBS5/Forms/confirmationForm', [
    'title' => __('Fetch events from remote server'),
    'model' => 'Server',
    'hiddenField' => 'event_ids',
    'url' => $baseurl . '/servers/pullSelectedEvents/' . (int)$server['Server']['id'],
    'message' => $message,
    'submitLabel' => __('Fetch'),
    'submitIcon' => 'circle-arrow-down',
    // Each event is downloaded from the remote in turn, in this request.
    'warning' => $count > 1
        ? __('Each event is pulled one by one, so this can take a while for a large selection.')
        : null,
]);
