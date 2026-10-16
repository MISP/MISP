<?php
// Overmind events index: the publish state as one glyph, its label and date in the tooltip.
$card = $row['EventCard'] ?? null;
if ($card === null) {
    return;
}
$glyphs = [
    'published' => ['is-pub', 'fa-circle-check'],
    'unpublished' => ['is-unpub', 'fa-floppy-disk'],
    'pending' => ['is-pending', 'fa-clock-rotate-left'],
];
[$class, $icon] = $glyphs[$card['state']];
$title = $this->EventIndex->stateTitle($row['Event'], $card['state']);
printf(
    '<span class="te-st %s" role="img" title="%s" aria-label="%s"><i class="fas %s" aria-hidden="true"></i></span>',
    $class,
    h($title),
    h($title),
    $icon
);
