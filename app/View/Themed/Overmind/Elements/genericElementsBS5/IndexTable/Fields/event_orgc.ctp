<?php
// Overmind events index: the creator org, and the reader's grade of it.
$orgc = $row['Orgc'] ?? [];
$ei = $this->EventIndex;
printf(
    '<span class="te-org">%s<a href="%s" title="%s">%s</a>%s</span>',
    $ei->orgTile($orgc, 20),
    h($baseurl . '/organisations/view/' . ($orgc['id'] ?? '')),
    h($ei->orgTitle($row)),
    h($orgc['name'] ?? ''),
    $ei->grade($row['EventCard']['grade'] ?? null, $orgc, $orgGrading ?? null)
);
