<div class="servers form">
<?php echo $this->Form->create('Server', array('novalidate'=>true));?>
	<fieldset>
		<legend>Edit Server</legend>
	<?php
		echo $this->Form->input('id');
		echo $this->Form->input('url', array(
				'label' => 'Base URL',
				'before' => $this->Html->div('forminfo', 'The base-url to the external server you want to sync with.<br/>Example: <i>https://foo.sig.mil.be</i>'),
			));
		echo $this->Form->input('organization', array(
				'label' => 'Organization',
				'before' => $this->Html->div('forminfo', 'The organization having the external server you want to sync with.<br/>Example: <i>BE</i>'),
			));
		echo $this->Form->input('authkey', array(
				'before' => $this->Html->div('forminfo', 'You can find the authentication key on your profile on the external server.'),
			));
		echo $this->Form->input('push', array(
				'div' => 'input clear',
				'before' => $this->Html->div('forminfo', 'Allow the <em>upload</em> of events and their attributes.'),
			));
		echo $this->Form->input('pull', array(
				'before' => $this->Html->div('forminfo', 'Allow the <em>download</em> of events and their attributes from the server.'),
			));
	?>
	</fieldset>
<?php
echo $this->Form->button('Edit', array('class' => 'btn btn-primary'));
echo $this->Form->end();
?>
</div>
<div class="actions">
	<ul class="nav nav-list">
		<li><?php echo $this->Html->link('List Servers', array('controller' => 'servers', 'action' => 'index'));?></li>
		<li><?php if ($isAclAdd && $me['org'] == 'ADMIN') echo $this->Html->link(__('New Server'), array('controller' => 'servers', 'action' => 'add')); ?></li>
		<li class="divider"></li>
		<li><?php echo $this->Form->postLink(__('Delete'), array('action' => 'delete', $this->Form->value('Server.id')), null, __('Are you sure you want to delete # %s?', $this->Form->value('Server.id'))); ?></li>
	</ul>
</div>

