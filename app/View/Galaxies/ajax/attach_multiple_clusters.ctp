<?php
    echo $this->Form->create('Galaxy', array('url' => array('controller' => 'galaxies', 'action' => 'attachMultipleClusters', $target_id, $target_type), 'style' => 'margin:0px;'));
    echo $this->Form->input('target_ids', array('type' => 'text'));
    echo $this->Form->input('attribute_ids', array('style' => 'display:none;', 'label' => false));
    echo $this->Form->end();
?>
