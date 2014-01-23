<div class="tag form">
<?php echo $this->Form->create('Tag');?>
	<fieldset>
		<legend>Add Tag</legend>
	<?php
		echo $this->Form->input('name', array(
		));
		echo $this->Form->input('colour', array(
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