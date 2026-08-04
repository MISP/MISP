<?php
$seed = mt_rand();

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
    if (empty($notesOpinions) && empty($relationshipsOutboundCount) && empty($relationshipsInboundCount)) {
        echo sprintf(
            '<i class="%s useCursorPointer analyst-data-fetcher" data-seed="%s" data-object-uuid="%s" data-object-type="%s" title="%s"></i>',
            $this->FontAwesome->getClass('sticky-note'),
            h($seed),
            h($object_uuid),
            Inflector::tableize(h($object_type)),
            __('Notes and opinions for this UUID')
        );
    } else {
        echo sprintf(
            '<span class="label label-info useCursorPointer analyst-data-fetcher highlight-on-hover" data-seed="%s" data-object-uuid="%s" data-object-type="%s">%s %s %s</span>',
            h($seed),
            h($object_uuid),
            Inflector::tableize(h($object_type)),
            sprintf(
                '<i class="%s useCursorPointer" title="%s"></i> %s',
                $this->FontAwesome->getClass('sticky-note'),
                __('Notes and opinions for this UUID'),
                $notesOpinionCount
            ),
            sprintf(
                '<i class="%s useCursorPointer" title="%s"></i> %s',
                $this->FontAwesome->getClass('arrow-up'),
                __('Outbound Relationships from this UUID'),
                $relationshipsOutboundCount
            ),
            sprintf(
                '<i class="%s useCursorPointer" title="%s"></i> %s',
                $this->FontAwesome->getClass('arrow-down'),
                __('Inbound Relationships to this UUID'),
                $relationshipsInboundCount
            ),
        );
    }
?>

