<?php
$fetchable = $fetchable ?? [];
$skipped = $skipped ?? [];
$isAll = !empty($isAll);
$count = count($fetchable);

if ($count === 0) {
    $message = $isAll
        ? __('No feed is enabled, so there is nothing to fetch.')
        : __('None of the selected feeds can be fetched.');
} elseif ($count === 1) {
    $message = __('Fetch and store all events from the feed "%s"?', $fetchable[0]['name']);
} elseif ($isAll) {
    $message = __('Fetch and store all events from every enabled feed (%s)?', $count);
} else {
    $message = __('Fetch and store all events from %s feeds?', $count);
}


$warnings = [];
foreach ($skipped as $skip) {
    $warnings[] = __('"%s" will be skipped: %s.', $skip['name'], $skip['reason']);
}
if ($count > 0 && empty($backgroundJobs)) {
    $warnings[] = __('Background jobs are disabled, so the feeds are pulled right now — this can take a while.');
}

echo $this->element('genericElementsBS5/Forms/confirmationForm', [
    'title' => __('Fetch feed data'),
    'model' => 'Feed',
    'hiddenField' => 'id',
    'url' => $baseurl . '/feeds/fetchSelectedFeeds',
    'message' => $message,
    'submitLabel' => __('Fetch'),
    'submitIcon' => 'circle-arrow-down',
    'warning' => empty($warnings) ? null : implode(' ', $warnings),
    'canProceed' => $count > 0,
]);
