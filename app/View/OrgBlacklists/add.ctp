<div class="orgBlacklist form">
<?php echo $this->Form->create('OrgBlacklist');?>
	<fieldset>
		<legend>Add Organisation Blacklist Entries</legend>
		<p>Simply paste a list of all the organisation UUIDs that you wish to block from being entered.</p>
	<?php
		echo $this->Form->input('uuids', array(
				'type' => 'textarea',
				'div' => 'input clear',
				'class' => 'input-xxlarge',
				'placeholder' => 'Enter a single or a list of UUIDs'
		));
		echo $this->Form->input('org_name', array(
				'div' => 'input clear',
				'class' => 'input-xxlarge',
				'label' => 'Organisation name',
				'placeholder' => '(Optional) The organisation name that the organisation is associated with'
		));
		echo $this->Form->input('comment', array(
				'type' => 'textarea',
				'div' => 'input clear',
				'class' => 'input-xxlarge',
				'placeholder' => '(Optional) Any comments you would like to add regarding this (or these) entries.'
		));
	?>
	</fieldset>
<?php
echo $this->Form->button('Add', array('class' => 'btn btn-primary'));
echo $this->Form->end();
?>
</div>
<?php
	echo $this->element('side_menu', array('menuList' => 'admin', 'menuItem' => 'orgBlacklistsAdd'));
?>
