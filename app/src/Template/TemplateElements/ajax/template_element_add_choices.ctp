<div class="popover_choice">
	<legend><?php echo __('Choose element type'); ?></legend>
	<div role="button" tabindex="0" aria-label="Add an attribute element" title="Add an attribute element" class="templateChoiceButton" onClick="templateAddElement('attribute', '<?php echo $id;?>');">Attribute</div>
	<div role="button" tabindex="0" aria-label="Add a file element" title="Add a file element" class="templateChoiceButton" onClick="templateAddElement('file', '<?php echo $id;?>');">File</div>
	<div role="button" tabindex="0" aria-label="Add a text description to the elements that follow" title="Add a text description to the elements that follow" class="templateChoiceButton" onClick="templateAddElement('text', '<?php echo $id;?>');">Text</div>
	<div role="button" tabindex="0" aria-label="Cancel" title="Cancel" class="templateChoiceButton templateChoiceButtonLast" onClick="cancelPopoverForm();">Cancel</div>
</div>
