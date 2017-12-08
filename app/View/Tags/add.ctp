<div class="tag form">
<?php echo $this->Form->create('Tag');?>
	<fieldset>
		<legend>Add Tag</legend>
	<?php
		echo $this->Form->input('name', array(
		));
		echo $this->Form->input('colour', array(
		));
		echo $this->Form->input('org_id', array(
				'options' => $orgs,
				'label' => 'Restrict tagging to org'
		));
		if ($isSiteAdmin) {
			echo $this->Form->input('user_id', array(
					'options' => $users,
					'label' => 'Restrict tagging to user'
			));
		}
	?>
		<div class="clear"></div>
	<?php
		echo $this->Form->input('exportable', array(
			'type' => 'checkbox', 'checked' => true
		));
	?>
		<div class="clear"></div>
	<?php
		echo $this->Form->input('hide_tag', array(
			'type' => 'checkbox', 'checked' => false
		));
	?>
	</fieldset>
<?php
echo $this->Form->button('Add', array('class' => 'btn btn-primary'));
echo $this->Form->end();
?>
</div>
<?php
	echo $this->element('side_menu', array('menuList' => 'tags', 'menuItem' => 'add'));
?>
<script>
	$(function(){
		$('#TagColour').colorpicker();
	});
</script>
