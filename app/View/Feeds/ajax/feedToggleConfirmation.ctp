<div class="confirmation">
    <?php
        echo $this->Form->create('Feed', array('style' => 'margin:0px;', 'id' => 'PromptForm'));
    ?>
    <legend><?php echo array('Disable', 'Enable')[$enable]; ?> Feed(s)</legend>
    <div style="padding-left:5px;padding-right:5px;padding-bottom:5px;">
        <p>Are you sure you want to <?php echo array('disable', 'enable')[$enable]; ?> the selected feeds?</p>
        <table>
            <tr>
                <td style="vertical-align:top">
                    <button role="button" tabindex="0" aria-label="Publish" title="Publish" id="PromptYesButton" class="btn btn-primary">Yes</button>
                </td>
                <td style="width:540px;">
                </td>
                <td style="vertical-align:top;">
                    <span role="button" tabindex="0" aria-label="Cancel" title="Cancel" class="btn btn-inverse" id="PromptNoButton" onClick="cancelPrompt();">No</span>
                </td>
            </tr>
        </table>
    </div>
    <?= $this->Form->end(); ?>
</div>
