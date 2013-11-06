<div class="logs form">
<?php echo $this->Form->create('Log', array('novalidate'=>true));?>
	<fieldset>
		<legend>Search Logs</legend>
	<?php
		echo $this->Form->input('email', array( 'label' => 'Email'));
		if ($orgRestriction == false) {
			echo $this->Form->input('org', array( 'label' => 'Organisation'));
		}
		echo $this->Form->input('action', array(
				'between' => $this->Html->div('forminfo', '', array('id' => 'LogActionDiv')),
				'div' => 'input clear'));
		echo $this->Form->input('title', array(
				'label' => 'Title',
				'div' => 'input clear'));
		echo $this->Form->input('change', array('label' => 'Change'));
	?>
	</fieldset>
<?php
echo $this->Form->button('Search', array('class' => 'btn btn-primary'));
echo $this->Form->end();
?>
</div>
<?php
	echo $this->element('side_menu', array('menuList' => 'logs', 'menuItem' => 'search'));
?>
