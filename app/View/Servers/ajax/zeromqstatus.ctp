<div class="confirmation">
<legend><?php echo __('ZeroMQ Server Status');?></legend>
    <div style="padding-left:5px;padding-right:5px;padding-bottom:5px;">
    <?php if (isset($time)): ?>
        <p><b><?php echo __('Start time');?></b>: <?php echo h($time); ?><br />
        <b><?php echo __('Settings read at');?></b>: <?php echo h($time2); ?><br />
        <b><?php echo __('Events processed');?></b>: <?php echo h($events); ?></p>
    <?php else: ?>
        <p><?php echo __('The ZeroMQ server is unreachable.');?></p>
    <?php endif; ?>
        <span role="button" tabindex="0" aria-label="<?php echo __('Cancel prompt');?>" title="<?php echo __('Cancel prompt');?>" class="btn btn-inverse" id="PromptNoButton" onClick="cancelPrompt();"><?php echo __('OK');?></span>
    </div>
</div>
