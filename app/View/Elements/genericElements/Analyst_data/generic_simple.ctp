<?php
if (empty($seed)) {
    $seed = mt_rand();
}

$notes = $analyst_data['notes'] ?? [];
$opinions = $analyst_data['opinions'] ?? [];
$relationships_outbound = $analyst_data['relationships_outbound'] ?? [];
$relationships_inbound = $analyst_data['relationships_inbound'] ?? [];

$notesOpinions = array_merge($notes, $opinions);
$notesOpinionsRelationships = array_merge($notesOpinions, $relationships_outbound);

if(!function_exists("countNotes")) {
    function countNotes($notesOpinions) {
        $notesTotalCount = count($notesOpinions);
        $notesCount = 0;
        $relationsCount = 0;
        foreach ($notesOpinions as $notesOpinion) {
            if ($notesOpinion['note_type'] == 2) { // relationship
                $relationsCount += 1;
            } else {
                $notesCount += 1;
            }
            if (!empty($notesOpinion['Note'])) {
                $nestedCounts = countNotes($notesOpinion['Note']);
                $notesTotalCount += $nestedCounts['total'];
                $notesCount += $nestedCounts['notesOpinions'];
                $relationsCount += $nestedCounts['relations'];
            }
            if (!empty($notesOpinion['Opinion'])) {
                $nestedCounts = countNotes($notesOpinion['Opinion']);
                $notesTotalCount += $nestedCounts['total'];
                $notesCount += $nestedCounts['notesOpinions'];
                $relationsCount += $nestedCounts['relations'];
            }
        }
        return ['total' => $notesTotalCount, 'notesOpinions' => $notesCount, 'relations' => $relationsCount];
    }
}
$counts = countNotes($notesOpinions);
$notesOpinionCount = $counts['notesOpinions'];
$relationshipsOutboundCount = count($relationships_outbound);
$relationshipsInboundCount = count($relationships_inbound);
$allCounts = [
    'notesOpinions' => $counts['notesOpinions'],
    'relationships_outbound' => $relationshipsOutboundCount,
    'relationships_inbound' => $relationshipsInboundCount,
];
?>

<?php
    echo $this->element('genericElements/Analyst_data/thread', [
        'seed' => $seed,
        'notes' => $notes,
        'opinions' => $opinions,
        'relationships_outbound' => $relationships_outbound,
        'relationships_inbound' => $relationships_inbound,
        'object_type' => $object_type,
        'object_uuid' => $object_uuid,
        'shortDist' => $shortDist,
        'allCounts' => $allCounts,
    ]);
?>
