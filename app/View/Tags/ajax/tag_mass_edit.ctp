<div class="attributes">
<?php
    echo $this->Form->create('Tag', array('url' => '/tags/editSelected', 'id' => 'PromptForm'));
?>
    <fieldset>
        <legend><?php echo __('Mass Edit Tags'); ?></legend>
        <div id="formWarning" class="message ajaxMessage"></div>
        <div class="add_attribute_fields">
            <?php
            echo $this->Form->input('tag_ids', array('style' => 'display:none;', 'label' => false));
            ?>
            <?php
            echo $this->Form->input('exportable', array(
                    'options' => array(__('No'), __('Yes'), __('Do not alter current settings')),
                    'data-content' => isset($attrDescriptions['signature']['formdesc']) ? $attrDescriptions['signature']['formdesc'] : $attrDescriptions['signature']['desc'],
                    'label' => __('Exportable?'),
                    'selected' => 2,
            ));
            ?>
            <?php
            echo $this->Form->input('hidden', array(
                    'options' => array(__('No'), __('Yes'), __('Do not alter current settings')),
                    'data-content' => isset($attrDescriptions['signature']['formdesc']) ? $attrDescriptions['signature']['formdesc'] : $attrDescriptions['signature']['desc'],
                    'label' => __('Hidden?'),
                    'selected' => 2,
            ));
            ?>
            <div class="input clear"></div>
        </div>
    </fieldset>
        <div class="overlay_spacing">
            <table>
                <tr>
                <td style="vertical-align:top">
                    <span id="submitButton" class="btn btn-primary" title="<?php echo __('Submit'); ?>" role="button" tabindex="0" aria-label="<?php echo __('Submit'); ?>" onClick="submitMassEditTag()"><?php echo __('Submit'); ?></span>
                </td>
                <td style="width:540px;">&nbsp;</td>
                <td style="vertical-align:top;">
                    <span class="btn btn-inverse" title="<?php echo __('Cancel'); ?>" role="button" tabindex="0" aria-label="<?php echo __('Cancel'); ?>" id="cancel_attribute_add"><?php echo __('Cancel'); ?></span>
                </td>
                </tr>
            </table>
        </div>
<script type="text/javascript">
    $(document).ready(function(){
        getSelectedTags();
    });
</script>
    <?php
        echo $this->Form->end();
    ?>
</div>