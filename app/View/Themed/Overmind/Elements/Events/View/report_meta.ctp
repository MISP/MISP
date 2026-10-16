<?php
/**
 * A report's sub line on the event page — the origin badge in an extended
 * view, the creator organisation and the last change. The overview card, its
 * picker, the Reports tab and the reader all show this same line.
 *
 * Parameters:
 *   event_id   int     the report's own event
 *   org        string  that event's creator organisation
 *   timestamp  int     the report's last change
 */
$parts = [];
if (($org ?? '') !== '') {
    $parts[] = h($org);
}
$parts[] = __('modified %s', $this->Time->time($timestamp ?? 0));

echo $this->element('Events/View/extension_origin', [
    'event_id' => (int)($event_id ?? 0),
    'compact' => true,
    'only_foreign' => true,
]);
echo implode(' · ', $parts);
