<?php
    echo $this->Form->create('Task', array(
        'id' => 'EnabledCheckboxForm' . h($id),
        'label' => false,
        'style' => 'display:none;',
        'url' => $baseurl . '/tasks/toggleEnabled/' . $id
    ));
    echo $this->Form->checkbox('enabled', array(
        'checked' => $enabled,
        'label' => false,
        'disabled' => !$isSiteAdmin,
    ));
    echo $this->Form->end();
?>
