<?php
// Overmind events index: when the event was last published.
$event = $row['Event'] ?? [];
$state = $row['EventCard']['state'] ?? null;
$published = (int)($event['publish_timestamp'] ?? 0);
if (!$published || $state === 'unpublished') {
    printf('<span class="te-faint" title="%s">—</span>', h(__('Never published')));
    return;
}
printf(
    '<span title="%s">%s</span>',
    h(__('Published %s', $this->EventIndex->utc($published))),
    h(gmdate('j M Y', $published))
);
