<div class="confirmation">
    <legend><?php echo __('ZeroMQ Server Status');?></legend>
    <div class="inner">
    <?php if (isset($time)): ?>
        <p><b><?php echo __('Reply time');?></b>: <?= $this->Time->time($time); ?><br>
        <b><?php echo __('Start time');?></b>: <?= $this->Time->time($time2); ?><br>
        <b><?php echo __('Events processed');?></b>: <?php echo h($events); ?><br>
        <b><?php echo __('Messages processed');?></b>: <?php echo h($messages); ?></p>
    <?php else: ?>
        <p><?php echo __('The ZeroMQ server is unreachable.');?></p>
    <?php endif; ?>
        <span role="button" tabindex="0" aria-label="<?php echo __('Cancel prompt');?>" title="<?php echo __('Cancel prompt');?>" class="btn btn-inverse" id="PromptNoButton" onClick="cancelPrompt();"><?php echo __('OK');?></span>
    </div>
</div>
