<div class="confirmation">
<?php
    echo $this->Form->create('Taxonomy', array('style' => 'margin:0px;', 'id' => 'PromptForm', 'url' => $baseurl . '/taxonomies/unhideTag'));
?>
<div class="hidden">
<?php
    echo $this->Form->input('nameList', array('value' => '{}'));
?>
    </div>
<?php
    echo $this->Form->input('taxonomy_id', array('type' => 'hidden', 'value' => $id));
?>
<legend><?php echo __('Unhide Tags');?></legend>
<div style="padding-left:5px;padding-right:5px;padding-bottom:5px;">
<p><?php echo __('Are you sure you want to unhide all selected tags?');?></p>
    <table>
        <tr>
            <td style="vertical-align:top">
                <span id="PromptYesButton" role="button" tabindex="0" aria-label="<?php echo __('Unhide all selected tags');?>" title="<?php echo __('Unhide all selected tags');?>" class="btn btn-primary" onClick="submitMassTaxonomyTag();"><?php echo __('Yes');?></span>
            </td>
            <td style="width:540px;">
            </td>
            <td style="vertical-align:top;">
                <span role="button" tabindex="0" aria-label="<?php echo __('Cancel');?>" title="<?php echo __('Cancel');?>" class="btn btn-inverse" id="PromptNoButton" onClick="cancelPrompt();"><?php echo __('No');?></span>
            </td>
        </tr>
    </table>
</div>
<script type="text/javascript">
    $(document).ready(function(){
        getSelectedTaxonomyNames();
    });
</script>
<?php
    echo $this->Form->end();
?>
</div>

