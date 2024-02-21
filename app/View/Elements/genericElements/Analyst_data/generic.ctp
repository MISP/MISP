<?php
$seed = mt_rand();

$notes = $analyst_data['notes'] ?? [];
$opinions = $analyst_data['opinions'] ?? [];
$relationships = $analyst_data['relationships'] ?? [];

$notesOpinions = array_merge($notes, $opinions);
$notesOpinionsRelationships = array_merge($notesOpinions, $relationships);

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
$relationshipsCount = count($relationships);
?>

<?php if (empty($notesOpinions) && empty($relationshipsCount)): ?>
    <i class="<?= $this->FontAwesome->getClass('sticky-note') ?> useCursorPointer node-opener-<?= $seed ?>" title="<?= __('Notes and opinions for this UUID') ?>"></i>
<?php else: ?>
    <span class="label label-info useCursorPointer node-opener-<?= $seed ?> highlight-on-hover">
        <i class="<?= $this->FontAwesome->getClass('sticky-note') ?> useCursorPointer" title="<?= __('Notes and opinions for this UUID') ?>"></i>
        <?= $notesOpinionCount; ?>
        <i class="<?= $this->FontAwesome->getClass('project-diagram') ?> useCursorPointer" title="<?= __('Relationships for this UUID') ?>"></i>
        <?= $relationshipsCount; ?>
    </span>
<?php endif; ?>

<script>


$(document).ready(function() {
    $('.node-opener-<?= $seed ?>').click(function() {
        openNotes(this)
    })

    function adjustPopoverPosition() {
        var $popover = $('.popover:last');
        $popover.css('top', Math.max($popover.position().top, 50) + 'px')
    }

    function openNotes(clicked) {
        openPopover(clicked, renderedNotes<?= $seed ?>, undefined, undefined, function() {
            adjustPopoverPosition()
            $(clicked).removeClass('have-a-popover') // avoid closing the popover if a confirm popover (like the delete one) is called
        })
    }
})
</script>

<?php
    echo $this->element('genericElements/Analyst_data/thread', [
        'seed' => $seed,
        'notes' => $notes,
        'opinions' => $opinions,
        'relationships' => $relationships,
        'object_type' => $object_type,
        'object_uuid' => $object_uuid,
        'shortDist' => $shortDist,
    ]);
?>