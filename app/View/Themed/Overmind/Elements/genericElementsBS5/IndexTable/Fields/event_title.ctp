<?php
// Overmind events index: the event's title, with a marker when it extends or is extended.
// `url` (%id%, %uuid%) points it elsewhere than the local event, for a remote one.
$event = $row['Event'] ?? [];
$card = $row['EventCard'] ?? null;
if (empty($event['id']) && empty($field['url'])) {
    return;
}
$titleUrl = empty($field['url'])
    ? $baseurl . '/events/view/' . (int)$event['id']
    : str_replace(['%id%', '%uuid%'], [(string)($event['id'] ?? ''), (string)($event['uuid'] ?? '')], $field['url']);
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
    h($titleUrl),
    h($event['info']),
    h($event['info'])
);
