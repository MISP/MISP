<div class="confirmation">
<?php
    echo $this->Form->create('Taxonomy', array(
            'style' => 'margin:0px;',
            'id' => 'PromptForm',
            'url' => array('controller' => 'taxonomies', 'action' => 'delete', $id)
    ));
?>
<legend><?php echo __('Taxonomy Deletion');?></legend>
<div style="padding-left:5px;padding-right:5px;padding-bottom:5px;">
<p><?php echo __('Are you sure you want to delete Taxonomy #<?php echo h($id); ?>?<br /> Associated tags will not be removed. You can reload the taxonomy at any time by updating your taxonomies.');?></p>
    <table>
        <tr>
            <td style="vertical-align:top">
                <?php
                    echo $this->Form->button(__('Yes'), array(
                            'type' => 'submit',
                            'class' => 'btn btn-primary'
                    ));
                ?>
            </td>
            <td style="width:540px;">
            </td>
            <td style="vertical-align:top;">
                <span role="button" tabindex="0" aria-label="<?php echo __('Cancel');?>" class="btn btn-inverse" id="PromptNoButton" onClick="cancelPrompt();"><?php echo __('No');?></span>
            </td>
        </tr>
    </table>
</div>
<?php
    echo $this->Form->end();
?>
</div>
