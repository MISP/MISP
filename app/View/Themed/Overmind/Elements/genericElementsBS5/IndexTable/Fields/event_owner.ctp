<?php
// Overmind events index: the org holding the event here.
$org = $row['Org'] ?? [];
echo $this->element('genericElementsBS5/Badges/organisation', [
    'org' => $org,
    'orgTitle' => __('Held here by %s', $org['name'] ?? ''),
]);
