<?php
    echo $this->Form->create('FavouriteTag', array('id' => 'FavouriteTagIndexForm', 'url' => $baseurl . '/favourite_tags/toggle'));
    echo $this->Form->input('data', array('label' => false, 'style' => 'display:none;'));
    echo $this->Form->end();
?>
