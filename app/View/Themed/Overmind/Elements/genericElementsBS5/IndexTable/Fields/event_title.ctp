<?php
// Overmind events index: the event's title, with a marker when it extends or is extended.
$event = $row['Event'] ?? [];
$card = $row['EventCard'] ?? null;
if (empty($event['id'])) {
    return;
}
$marker = '';
if ($card !== null && (!empty($card['extends']) || !empty($card['extended_by']))) {
    $says = [];
    if (!empty($card['extends'])) {
        $says[] = $card['extends']['id']
            ? __('Extends #%s %s', $card['extends']['id'], $card['extends']['info'])
            : __('Extends %s, which is not available here', $card['extends']['uuid']);
    }
    if (!empty($card['extended_by'])) {
        $says[] = $this->EventIndex->plural((int)$card['extended_by'], 'Extended by %s event', 'Extended by %s events');
    }
    $marker = sprintf(
        '<i class="fas %s te-extmark" role="img" title="%s" aria-label="%s"></i>',
        empty($card['extends']) ? 'fa-code-branch' : 'fa-turn-up fa-rotate-90',
        h(implode("\n", $says)),
        h(implode('. ', $says))
    );
}
printf(
    '<span class="te-titlewrap">%s<a class="te-title" href="%s" title="%s">%s</a></span>',
    $marker,
    h($baseurl . '/events/view/' . (int)$event['id']),
    h($event['info']),
    h($event['info'])
);
