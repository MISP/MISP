<?php
    echo $this->Form->create('Taxonomy', array(
        'id' => 'RequiredCheckboxForm' . h($id),
        'label' => false,
        'style' => 'display:none;',
        'url' => $baseurl . '/taxonomies/toggleRequired/' . $id
    ));
    echo $this->Form->checkbox('required', array(
        'checked' => $required,
        'label' => false,
        'disabled' => !$isSiteAdmin,
        'class' => 'required-toggle'
    ));
    echo $this->Form->end();
?>
