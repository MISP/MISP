<div class="servers form">
<?php echo $this->Form->create('Server');?>
	<fieldset>
		<legend><?php echo __('Add Server'); ?></legend>
	<?php
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
					'before' => $this->Html->div('forminfo', 'Allow the <em>upload</em> of events and their attributes.'),
			));
		echo $this->Form->input('pull', array(
					'before' => $this->Html->div('forminfo', 'Allow the <em>download</em> of events and their attributes from the server.'),
			));
	?>
	</fieldset>
<?php echo $this->Form->end(__('Submit'));?>
</div>