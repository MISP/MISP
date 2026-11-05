<?php
// Overmind events index: the creator org, and the reader's grade of it. A
// remote event's org has no local record to link to.
$orgc = $row['Orgc'] ?? [];
$ei = $this->EventIndex;
$name = empty($orgc['id'])
    ? sprintf('<span title="%s">%s</span>', h($ei->orgTitle($row)), h($orgc['name'] ?? ''))
    : sprintf(
        '<a href="%s" title="%s">%s</a>',
        h($baseurl . '/organisations/view/' . $orgc['id']),
        h($ei->orgTitle($row)),
        h($orgc['name'] ?? '')
    );
printf(
    '<span class="te-org">%s%s%s</span>',
    $ei->orgTile($orgc, 20),
    $name,
    $ei->grade($row['EventCard']['grade'] ?? null, $orgc, $orgGrading ?? null)
);
