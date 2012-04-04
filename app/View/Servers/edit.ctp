<div class="servers form">
<?php echo $this->Form->create('Server');?>
	<fieldset>
		<legend><?php echo __('Edit Server'); ?></legend>
	<?php
		echo $this->Form->input('id');
		echo $this->Form->input('url', array(
		            'label' => 'Base URL',
		            'before' => $this->Html->div('forminfo', 'The base-url to the external server you want to sync with.<br/>Example: <i>https://foo.sig.mil.be</i>'),
		    ));
		echo $this->Form->input('authkey', array(
		            'before' => $this->Html->div('forminfo', 'You can find the authentication key on your profile on the external server.<br/><i>Leave empty if you don\'t want to change it</i>.'),
		    ));
		echo $this->Form->input('push', array(
		            'before' => $this->Html->div('forminfo', 'Allow the <em>upload</em> of events and their attributes.'),
		    ));
		echo $this->Form->input('pull', array(
		            'before' => $this->Html->div('forminfo', 'Allow the <em>download</em> of events and their attributes from the server.'),
		    ));
	?>
	</fieldset>
<?php echo $this->Form->end(__('Submit'));?>
</div>
<div class="actions">
	<ul>

		<li><?php echo $this->Form->postLink(__('Delete'), array('action' => 'delete', $this->Form->value('Server.id')), null, __('Are you sure you want to delete # %s?', $this->Form->value('Server.id'))); ?></li>
		<li>&nbsp;</li>
		<?php echo $this->element('actions_menu'); ?>
	</ul>
</div>
