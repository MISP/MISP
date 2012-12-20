<div class="regexp form">
<?php echo $this->Form->create('Regexp');?>
	<fieldset>
		<legend><?php echo __('Edit Import Regexp'); ?></legend>
	<?php
		echo $this->Form->input('id');
		echo $this->Form->input('regexp');
		echo $this->Form->input('replacement');
	?>
	</fieldset>
<?php echo $this->Form->end(__('Submit'));?>
</div>
<div class="actions">
	<ul>
		<?php echo $this->element('actions_menu'); ?>
	</ul>
</div>