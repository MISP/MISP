<?php
echo $this->Form->create('Noticelist', array('id' => 'NoticelistIndexForm', 'url' => $baseurl . '/noticelists/toggleEnable'));
echo $this->Form->input('data', array('id' => 'NoticelistData', 'label' => false, 'style' => 'display:none;'));
echo $this->Form->end();
