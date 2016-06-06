<?php
	echo $this->Form->create('FavouriteTag', array('id' => 'FavouriteTagIndexForm', 'url' => '/favourite_tags/toggle'));
	echo $this->Form->input('data', array('label' => false, 'style' => 'display:none;'));
	echo $this->Form->end();
?>
