<?php
$mayModify = (($isAclModify && $this->request->data['Event']['user_id'] == $me['id']) || ($isAclModifyOrg && $this->request->data['Event']['orgc'] == $me['org']));
$mayPublish = ($isAclPublish && $this->request->data['Event']['orgc'] == $me['org']);
?>
<div class="events form">
<?php echo $this->Form->create('Event');?>
	<fieldset>
		<legend><?php echo __('Contact organization reporting event ', true) . $this->Form->value('Event.id'); ?></legend>
		<p>You are about to contact the organization that reported event <?php echo $this->Form->value('Event.id'); ?>.<br/>
		Feel free to add a custom message that will be sent to the reporting organization. <br/>
		Your email address and details about the event will be added automagically to the message.</p>
	<?php
		echo $this->Form->input('message', array(
			'type' => 'textarea',
			'class' => 'input-xxlarge',
		));
	?>
		<div class="input clear"></div>
	<?php
		echo $this->Form->input('person', array(
			'label' => __('Submit only to the person that created the event', true),
			'type' => 'checkbox',
			'class' => 'clear',
			// 'after' => $this->Html->div('forminfo', __('By selecting this box you will contact the creator of the event only.', true)),
		));
	?>
		<div class="input clear">
	<?php
		echo $this->Form->button('Submit', array('class' => 'btn btn-primary'));
		echo $this->Form->end();
	?>
		</div>
	</fieldset>

</div>
<?php 
	$event = $this->data;
	echo $this->element('side_menu', array('menuList' => 'event', 'menuItem' => 'contact', 'event' => $event));
?>
