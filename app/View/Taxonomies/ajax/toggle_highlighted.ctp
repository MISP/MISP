<?php
    echo $this->Form->create('Taxonomy', array(
        'id' => 'HighlightedCheckboxForm' . h($id),
        'label' => false,
        'style' => 'display:none;',
        'url' => $baseurl . '/taxonomies/toggleHighlighted/' . $id
    ));
    echo $this->Form->checkbox('highlighted', array(
        'checked' => $highlighted,
        'label' => false,
        'disabled' => !$isSiteAdmin,
        'class' => 'highlighted-toggle'
    ));
    echo $this->Form->end();
?>
