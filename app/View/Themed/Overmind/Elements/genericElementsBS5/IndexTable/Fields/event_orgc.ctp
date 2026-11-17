<?php
// Overmind events index: the creator org. A remote event's org has no local
// record to link to.
echo $this->element('genericElementsBS5/Badges/organisation', [
    'org' => $row['Orgc'] ?? [],
    'orgTitle' => $this->EventIndex->orgTitle($row),
]);
