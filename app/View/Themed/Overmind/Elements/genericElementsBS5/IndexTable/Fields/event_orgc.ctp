<?php
// Overmind events index: the creator org, and the reader's grade of it. A
// remote event's org has no local record to link to.
$orgc = $row['Orgc'] ?? [];
$ei = $this->EventIndex;
echo $ei->orgCell(
    $orgc,
    $ei->orgTitle($row),
    $ei->grade($row['EventCard']['grade'] ?? null, $orgc, $orgGrading ?? null)
);
