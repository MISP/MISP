<div class="confirmation">
    <legend><?php echo __('Errors');?></legend>
    <div style="padding-left:5px;padding-right:5px;padding-bottom:5px;">
        <div id="flashErrorMessageContent" style="overflow-y: auto;"><?php echo h($message); ?></div>
        <span role="button" tabindex="0" aria-label="<?php echo __('Cancel');?>" title="<?php echo __('Cancel');?>" class="btn btn-inverse" id="PromptNoButton" onClick="cancelPopoverForm();"><?php echo __('Close');?></span>
    </div>
</div>
