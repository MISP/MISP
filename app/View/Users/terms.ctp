<div class="users form">
<h2>CyDefSIG Terms and Conditions</h2>
<p>Please add your terms and conditions here</p>
<?php
if (!$termsaccepted) {
	echo $this->Form->create('User');
	echo $this->Form->hidden('termsaccepted', array('default' => '1'));
	echo $this->Form->end(__('Accept Terms', true));
}
?>
</div>

<div class="actions">
	<ul>
		<?php echo $this->element('actions_menu'); ?>
	</ul>
</div>
