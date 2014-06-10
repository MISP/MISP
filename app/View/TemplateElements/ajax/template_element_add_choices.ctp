<div class="template_element_add_choice">
<?php 
	echo $this->Form->create('Attribute', array('id'));
?>
	<legend><?php echo __('Choose element type'); ?></legend>
	<div class="templateChoiceButton" onClick="templateAddElement('attribute', '<?php echo $id;?>');">Attribute</div>
	<div class="templateChoiceButton" onClick="templateAddElement('attachment', '<?php echo $id;?>');">Attachment</div>
	<div class="templateChoiceButton" onClick="templateAddElement('text', '<?php echo $id;?>');">Text</div>
	<div class="templateChoiceButton" onClick="cancelPopoverForm();">Cancel</div>
</div>