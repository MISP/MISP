<?php
/**
 * Hover target over the colour band of a row carried in from another event
 * in an extended / extending view, naming that event. Renders nothing for the
 * viewed event's own rows.
 *
 * Parameters:
 *   event_id  int  the row's own event
 *
 * Read from the view: $extensionEvents
 */
$origin = ($extensionEvents ?? [])[(int)($event_id ?? 0)] ?? null;
if ($origin === null || $origin['role'] === 'self') {
    return;
}
$relation = $origin['role'] === 'extension'
    ? __('an event that extends this one')
    : __('the event this one extends');
$orgName = $origin['Orgc']['name'] ?? '';
$title = sprintf(
    '#%d %s%s — %s',
    (int)$origin['id'],
    (string)$origin['info'],
    $orgName === '' ? '' : ' · ' . $orgName,
    $relation
);
?>
<span class="evt-origin-band" title="<?= h($title) ?>" aria-label="<?= h($title) ?>" data-evt-origin></span>
