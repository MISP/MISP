<div class="confirmation">
<?php echo $this->Form->create('Event', [
    'style' => 'margin:0px;', 'id' => 'PromptForm',
    'url' => $baseurl . '/events/massPublish/' . $ids
]); ?>
    <legend><?= __('Publish (no email) %d event(s)?', count($idList)) ?></legend>
    <div style="padding:5px;">
        <p><?= __('Are you sure you want to publish but do NOT send alert emails for these events?') ?></p>
        <button class="btn btn-primary" id="PromptYesButton"><?= __('Yes') ?></button>
        <span class="btn btn-inverse" id="PromptNoButton" onclick="cancelPrompt()"><?= __('No') ?></span>
    </div>
<?php echo $this->Form->end(); ?>
</div>