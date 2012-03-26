<div class="attributes form">
<?php echo $this->Form->create('Attribute');?>
	<fieldset>
		<legend><?php echo __('Search Attribute'); ?></legend>
	<?php
		echo $this->Form->input('keyword');
		echo $this->Form->input('type');
		echo $this->Form->input('category');
	?>
	</fieldset>
<?php echo $this->Form->end(__('Search', true));?>
</div>
<div class="actions">
	<ul>
        <?php echo $this->element('actions_menu'); ?>
	</ul>
</div>