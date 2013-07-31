<?php echo $this->element('bread_crumbs'); ?>
<div class="servers form">
<?php echo $this->Form->create('Server');?>
	<fieldset>
		<legend>Add Server</legend>
	<?php
		echo $this->Form->input('url', array(
				'label' => 'Base URL',
				'after' => $this->Html->div('forminfo', 'The base-url to the external server you want to sync with.<br/>Example: <i>https://foo.sig.mil.be</i>'),
			));
		echo $this->Form->input('organization', array(
				'label' => 'Organization',
				'after' => $this->Html->div('forminfo', 'The organization having the external server you want to sync with.<br/>Example: <i>BE</i>'),
			));
		echo $this->Form->input('authkey', array(
				'after' => $this->Html->div('forminfo', 'You can find the authentication key on your profile on the external server.'),
			));
		?>
		<div class = "input clear"></div>
		<?php
		echo $this->Form->input('push', array(
				'after' => $this->Html->div('forminfo', 'Allow the <em>upload</em> of events and their attributes.'),
			));
		echo $this->Form->input('pull', array(
				'after' => $this->Html->div('forminfo', 'Allow the <em>download</em> of events and their attributes from the server.'),
			));
	?>
	</fieldset>
<?php
echo $this->Form->button('Add', array('class' => 'btn btn-primary'));
echo $this->Form->end();
?>
</div>
<div class="actions <?php echo $debugMode;?>">
	<ul class="nav nav-list">
		<li><?php echo $this->Html->link('List Servers', array('controller' => 'servers', 'action' => 'index'));?></li>
		<li class="active"><?php if ($isAclAdd && $me['org'] == 'ADMIN') echo $this->Html->link(__('New Server'), array('controller' => 'servers', 'action' => 'add')); ?></li>

	</ul>
</div>
