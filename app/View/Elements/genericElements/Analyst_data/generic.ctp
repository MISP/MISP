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
]
?>

<?php if (empty($notesOpinions) && empty($relationshipsOutboundCount) && empty($relationshipsInboundCount)): ?>
    <i class="<?= $this->FontAwesome->getClass('sticky-note') ?> useCursorPointer node-opener-<?= $seed ?>" title="<?= __('Notes and opinions for this UUID') ?>"></i>
<?php else: ?>
    <span class="label label-info useCursorPointer node-opener-<?= $seed ?> highlight-on-hover">
        <i class="<?= $this->FontAwesome->getClass('sticky-note') ?> useCursorPointer" title="<?= __('Notes and opinions for this UUID') ?>"></i>
        <?= $notesOpinionCount; ?>
        <i class="<?= $this->FontAwesome->getClass('arrow-up') ?> useCursorPointer" title="<?= __('Outbound Relationships from this UUID') ?>"></i>
        <?= $relationshipsOutboundCount; ?>
        <i class="<?= $this->FontAwesome->getClass('arrow-down') ?> useCursorPointer" title="<?= __('Inbound Relationships to this UUID') ?>"></i>
        <?= $relationshipsInboundCount; ?>
    </span>
<?php endif; ?>

<script>


$(document).ready(function() {
    $('.node-opener-<?= $seed ?>').click(function() {
        openNotes<?= $seed ?>(this)
    })
})
</script>

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