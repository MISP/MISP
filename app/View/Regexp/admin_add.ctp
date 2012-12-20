<div class="regexp form">
<?php echo $this->Form->create('Regexp');?>
	<fieldset>
		<legend><?php echo __('Add Import Regexp'); ?></legend>
	<?php
		echo $this->Form->input('regexp');
		echo $this->Form->input('replacement');
	?>
	</fieldset>
<?php echo $this->Form->end(__('Submit'));?>
</div>
<div class="actions">
	<h3><?php echo __('Actions'); ?></h3>
	<ul>
		<?php echo $this->element('actions_menu'); ?>
	</ul>
</div>
