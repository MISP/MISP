<div class="signatures form">
<?php echo $this->Form->create('Signature');?>
	<fieldset>
		<legend><?php __('Search Signature'); ?></legend>
	<?php
		echo $this->Form->input('keyword');
	?>
	</fieldset>
<?php echo $this->Form->end(__('Search', true));?>
</div>
<div class="actions">
	<h3><?php __('Actions'); ?></h3>
	<ul>
        <?php echo $this->element('actions_menu'); ?>
	</ul>
</div>