<?php
echo $this->Form->create('Warninglist', array('id' => 'WarninglistIndexForm', 'url' => $baseurl . '/warninglists/toggleEnable'));
echo $this->Form->input('data', array('id' => 'WarninglistData', 'label' => false, 'style' => 'display:none;'));
echo $this->Form->end();
