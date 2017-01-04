<div class="popover_choice">
	<legend><?php echo __('Choose element type'); ?></legend>
	<div class="templateChoiceButton" onClick="templateAddElement('attribute', '<?php echo $id;?>');">Attribute</div>
	<div class="templateChoiceButton" onClick="templateAddElement('file', '<?php echo $id;?>');">File</div>
	<div class="templateChoiceButton" onClick="templateAddElement('text', '<?php echo $id;?>');">Text</div>
	<div class="templateChoiceButton templateChoiceButtonLast" onClick="cancelPopoverForm();">Cancel</div>
</div>
