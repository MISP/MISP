<div class="confirmation">
<?php echo $this->Form->create('Event', [
    'style' => 'margin:0px;', 'id' => 'PromptForm',
    'url' => $baseurl . '/events/massUnpublish/' . $ids
]); ?>
    <legend><?= __('Unpublish %d event(s)?', count($idList)) ?></legend>
    <div style="padding:5px;">
        <p><?= __('Are you sure you want to unpublish these events?') ?></p>
        <button class="btn btn-primary" id="PromptYesButton"><?= __('Yes') ?></button>
        <span class="btn btn-inverse" id="PromptNoButton" onclick="cancelPrompt()"><?= __('No') ?></span>
    </div>
<?php echo $this->Form->end(); ?>
</div>