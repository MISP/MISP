<div class="confirmation">
    <?php
        echo $this->Form->create('EventBlocklist', array('style' => 'margin:0px;', 'id' => 'PromptForm'));
        echo $this->Form->input('ids', array(
                'type' => 'hidden',
                'div' => 'hidden',
                'value' => json_encode($event_ids)
        ));
    ?>
    <legend><?php echo __('Delete blocklisted events'); ?></legend>
    <div style="padding-left:5px;padding-right:5px;padding-bottom:5px;">
        <p><?php echo __('Are you sure you want to delete from the blocklist the selected events?'); ?></p>
        <table>
            <tr>
                <td style="vertical-align:top">
                    <span role="button" tabindex="0" aria-label="Publish" title="Publish" id="PromptYesButton" class="btn btn-primary" onClick="submitPublish()">Yes</span>
                </td>
                <td style="width:540px;">
                </td>
                <td style="vertical-align:top;">
                    <span role="button" tabindex="0" aria-label="Cancel" title="Cancel" class="btn btn-inverse" id="PromptNoButton" onClick="cancelPrompt();">No</span>
                </td>
            </tr>
        </table>
    </div>
    <?php
        echo $this->Form->end();
    ?>
</div>
