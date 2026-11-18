<?php
/**
 * One object of the objects index, opened under its table row or inside its
 * card: its attributes as the event's Objects tab draws them in the same view
 * (a table, or the attribute cards), read-only, and the way to the event.
 */
$objId = (int)$object['id'];
$references = $object['ObjectReference'] ?? [];
?>
<div class="oi-card">
    <?= $this->element($asTable ? 'Objects/object_attribute_table' : 'Objects/object_attribute_list', [
        'attrs' => $object['Attribute'] ?? [],
        'canEdit' => false,
        'canTag' => false,
        'showActions' => false,
        'readonly' => true,
    ]) ?>
    <?php
    $footContent = '';
    if (!empty($references)) {
        $footContent .= $this->element('Objects/object_relationships', [
            'references' => $references,
            'objId' => $objId,
            'eventId' => $eventId,
            'canEdit' => false,
            'menuPrefix' => 'oiRels',
        ]);
    }
    $footContent .= '<a class="btn btn-sm btn-outline-primary ms-auto" href="'
        . h($baseurl . '/events/view/' . (int)$eventId . '/object:' . $objId . '#tab-objects') . '">'
        . '<i class="fas fa-arrow-up-right-from-square me-1"></i>' . __('Open in event') . '</a>';
    ?>
    <?= $this->element('Objects/object_foot', [
        'object' => $object,
        'content' => $footContent,
    ]) ?>
</div>
