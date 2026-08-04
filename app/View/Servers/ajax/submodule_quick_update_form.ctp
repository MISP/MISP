<?php
echo $this->Form->create('Server', array(
    'id' => 'form_update_' . h($submodule),
    'url' => array('action' => 'updateSubmodule'),
    'div' => false,
    'style' => 'margin: 0px; display: inline-block;')
);
echo $this->Form->hidden('Server.submodule', array('value' => h($submodule)));
echo $this->Form->end();
?>
