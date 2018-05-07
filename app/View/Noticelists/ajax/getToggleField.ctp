<?php
echo $this->Form->create('Noticelist', array('id' => 'NoticelistIndexForm', 'url' => '/noticelists/toggleEnable'));
echo $this->Form->input('data', array('id' => 'NoticelistData', 'label' => false, 'style' => 'display:none;'));
echo $this->Form->end();
