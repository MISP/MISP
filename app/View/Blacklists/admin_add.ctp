<div class="whitelist form">
<?php echo $this->Form->create('Blacklist');?>
	<fieldset>
		<legend><?php echo __('Add Import Blacklist');?></legend>
	<?php
		echo $this->Form->input('name');
	?>
	</fieldset>
<?php echo $this->Form->end(__('Submit'));?>
</div>
<div class="actions">
	<h3><?php echo __('Actions');?></h3>
	<ul>
		<?php echo $this->element('actions_menu');?>
	</ul>
</div>
