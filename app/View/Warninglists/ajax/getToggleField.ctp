<?php
	echo $this->Form->create('Warninglist', array('id' => 'enable_form_' . $item['Warninglist']['id'], 'url' => '/warninglists/toggleEnable/' . $item['Warninglist']['id']));
	echo $this->Form->input('enable', array('id' => 'enable_checkbox_' . $item['Warninglist']['id'], 'checked' => $item['Warninglist']['enabled'], 'label' => false, 'onclick' => 'toggleSetting(event, "warninglist_enable", "' . $item['Warninglist']['id'] . '")'));
	echo $this->Form->end();
?>