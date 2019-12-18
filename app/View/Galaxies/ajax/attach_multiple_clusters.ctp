<?php
    $url = sprintf(
        '/galaxies/attachMultipleClusters/%s/%s/local:%s',
        $target_id,
        $target_type,
        $local ? '1' : '0'
    );
    echo $this->Form->create('Galaxy', array('url' => $url, 'style' => 'margin:0px;'));
    echo $this->Form->input('target_ids', array('type' => 'text'));
    echo $this->Form->input('attribute_ids', array('style' => 'display:none;', 'label' => false));
    echo $this->Form->end();
?>
