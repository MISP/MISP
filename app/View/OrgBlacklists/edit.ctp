<div class="orgBlacklist form">
<?php echo $this->Form->create('OrgBlacklist');?>
	<fieldset>
		<legend>Add Event Blacklist Entries</legend>
		<p>Simply paste a list of all the event UUIDs that you wish to block from being entered.</p>
	<?php
		echo $this->Form->input('org_name', array(
				'div' => 'input clear',
				'class' => 'input-xxlarge',
				'label' => 'Creating organisation',
				'default' => $blockEntry['OrgBlacklist']['org_name'],
		));
		echo $this->Form->input('comment', array(
				'type' => 'textarea',
				'div' => 'input clear',
				'class' => 'input-xxlarge',
				'default' => $blockEntry['OrgBlacklist']['comment'],
		));
	?>
	</fieldset>
<?php
echo $this->Form->button('Edit', array('class' => 'btn btn-primary'));
echo $this->Form->end();
?>
</div>
<?php
	echo $this->element('side_menu', array('menuList' => 'admin', 'menuItem' => 'orgBlacklistsAdd'));
?>
