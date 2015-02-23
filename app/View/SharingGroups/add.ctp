<div class="users form">
<?php echo $this->Form->create('SharingGroup');?>
	<fieldset>
		<legend><?php echo __('New Sharing Group'); ?></legend>
		<?php
			echo $this->Form->input('name', array('div' => 'clear', 'label' => 'Releasable to', 'placeholder' => 'For example: Belgium'));
			echo $this->Form->input('description', array('label' => 'Description', 'div' => 'clear', 'class' => 'input-xxlarge', 'type' => 'textarea', 'placeholder' => 'A description of the sharing group.'));
			echo $this->Form->input('distribution', array(
					'options' => array($distributionLevels),
					'label' => 'Distribution',
					//'selected' => $initialDistribution,
			));
		?>
			<div class="clear"></div>
		<?php 
			echo $this->Form->input('pushable', array('label' => 'Events pushable', 'type' => 'checkbox', 'title' => 'MISP will look for the eligible organisations on connected communities if this is checked. If left unchecked, then any event in this sharing group is blocked from being pushed.'));
		
		?>
			<div class="clear"></div>
		<?php 
			echo $this->Form->input('extendable', array('label' => 'Extendable by partners', 'class' => 'input-xxlarge', 'type' => 'checkbox', 'title' => 'If the sharing group is extendable, then any user that is of an organisation within the sharing group can add new organisations to the group.'));
		?>
			<div class="clear"></div>
		<?php 
			echo $this->Form->input('active', array('label' => 'Make the sharing group active', 'type' => 'checkbox', 'title' => 'Active sharing groups can be selected by users of the local instance when creating events. Generally, sharing groups received through synchronisation will have this disabled until manually enabled.'));
		?>
	</fieldset>
<?php echo $this->Form->button(__('Submit'), array('class' => 'btn btn-primary'));
	echo $this->Form->end(); 
?>
</div>
<?php 
	echo $this->element('side_menu', array('menuList' => 'admin', 'menuItem' => 'addOrg'));
?>
<script type="text/javascript">

</script>
