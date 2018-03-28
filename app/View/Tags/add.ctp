<div class="tag form">
<?php echo $this->Form->create('Tag');?>
	<fieldset>
		<legend><?php echo __('Add Tag');?></legend>
	<?php
		echo $this->Form->input('name', array(
			'class' => 'form-control'
		));
		echo $this->Form->input('colour', array(
			'class' => 'form-control'
		));
		echo $this->Form->input('org_id', array(
				'options' => $orgs,
				'label' => __('Restrict tagging to org'),
				'class' => 'form-control'
		));
		if ($isSiteAdmin) {
			echo $this->Form->input('user_id', array(
					'options' => $users,
					'label' => __('Restrict tagging to user'),
					'class' => 'form-control'
			));
		}
	?>
		<div class="clear"></div>
	<?php
		echo $this->Form->input('exportable', array(
			'type' => 'checkbox', 'checked' => true,
			'class' => 'form-check-input'
		));
	?>
		<div class="clear"></div>
	<?php
		echo $this->Form->input('hide_tag', array(
			'type' => 'checkbox', 'checked' => false,
			'class' => 'form-check-input'
		));
	?>
	</fieldset>
<?php
echo $this->Form->button(__('Add'), array('class' => 'btn btn-primary'));
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
