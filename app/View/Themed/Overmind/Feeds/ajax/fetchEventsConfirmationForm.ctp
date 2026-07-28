<?php
$count = count($uuids);
$message = $count > 1
    ? __('Fetch and save %s events from this feed on your instance?', $count)
    : __('Fetch and save event %s from this feed on your instance?', h($uuids[0]));

echo $this->element('genericElementsBS5/Forms/confirmationForm', [
    'title' => __('Fetch events from feed'),
    'model' => 'Feed',
    'hiddenField' => 'uuids',
    'url' => $baseurl . '/feeds/getSelectedEvents/' . (int)$feed['Feed']['id'],
    'message' => $message,
    'submitLabel' => __('Fetch'),
    'submitIcon' => 'circle-arrow-down',
    'warning' => $count > 1
        ? __('Each event is downloaded one by one, so this can take a while for a large selection.')
        : null,
]);
