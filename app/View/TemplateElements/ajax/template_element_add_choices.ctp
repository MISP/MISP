<div class="popover_choice">
    <legend><?php echo __('Choose element type'); ?></legend>
    <div role="button" tabindex="0" aria-label="<?php echo __('Add an attribute element');?>" title="<?php echo __('Add an attribute element');?>" class="templateChoiceButton" onClick="templateAddElement('attribute', '<?php echo $id;?>');"><?php echo __('Attribute');?></div>
    <div role="button" tabindex="0" aria-label="<?php echo __('Add a file element');?>" title="Add a file element" class="templateChoiceButton" onClick="templateAddElement('file', '<?php echo $id;?>');"><?php echo __('File');?></div>
    <div role="button" tabindex="0" aria-label="<?php echo __('Add a text description to the elements that follow');?>" title="<?php echo __('Add a text description to the elements that follow');?>" class="templateChoiceButton" onClick="templateAddElement('text', '<?php echo $id;?>');"><?php echo __('Text');?></div>
    <div role="button" tabindex="0" aria-label="<?php echo __('Cancel');?>" title="<?php echo __('Cancel');?>" class="templateChoiceButton templateChoiceButtonLast" onClick="cancelPopoverForm();"><?php echo __('Cancel');?></div>
</div>
