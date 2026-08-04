<?php
    echo $this->Form->create('ObjectRelationship', array(
        'id' => 'HighlightedCheckboxForm' . h($name),
        'label' => false,
        'style' => 'display:none;',
        'url' => $baseurl . '/object_relationships/toggleHighlighted/' . $name
    ));
    echo $this->Form->checkbox('highlighted', array(
        'checked' => $highlighted,
        'label' => false,
        'disabled' => !$isSiteAdmin,
        'class' => 'highlighted-toggle'
    ));
    echo $this->Form->end();
?>
