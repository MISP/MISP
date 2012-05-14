<?php
echo $this->Session->flash('auth');
echo $this->Form->create('User', array('action' => 'login'));
echo $this->Form->inputs(array(
	'legend' => __('Login', true),
	'email',
	'password' => array('autocomplete' => 'off')
));

echo $this->Form->end('Login');
?>
