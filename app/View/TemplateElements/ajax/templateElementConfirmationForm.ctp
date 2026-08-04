<div class="confirmation">
<?php
    echo $this->Form->create('TemplateElement', array('style' => 'margin:0px;', 'id' => 'PromptForm'));
?>
<legend><?php echo __('Template Element Deletion');?></legend>
<div style="padding-left:5px;padding-right:5px;padding-bottom:5px;">
<p><?php echo __('Are you sure you want to delete Template Element #%s?', $id);?></p>
    <table>
        <tr>
            <td style="vertical-align:top">
                <span id="PromptYesButton" class="btn btn-primary" onClick="submitDeletion(<?php echo $template_id; ?>, 'delete', 'template_elements', <?php echo $id;?>)"><?php echo __('Yes');?></span>
            </td>
            <td style="width:540px;">
            </td>
            <td style="vertical-align:top;">
                <span class="btn btn-inverse" id="PromptNoButton" onClick="cancelPrompt();"><?php echo __('No');?></span>
            </td>
        </tr>
    </table>
</div>
<?php
    echo $this->Form->end();
?>
</div>
