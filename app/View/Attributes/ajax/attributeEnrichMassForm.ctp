<div class="attributes">
<?php
    echo $this->Form->create('Attribute', array('url' => $baseurl . '/attributes/enrichSelected/' . $id));
?>
    <fieldset>
        <legend><?php echo __('Enrich Selected Attributes'); ?></legend>
        <div id="formWarning" class="message ajaxMessage"></div>
        <div class="add_attribute_fields">
            <?php
            echo $this->Form->hidden('event_id', array('value' => $id));
            echo $this->Form->hidden('attribute_ids', array('value' => json_encode($selectedAttributeIds)));
            if (!empty($modules['modules'])) {
                echo '<p>' . __('Select the enrichments you wish to run on the %s selected attributes', count($selectedAttributeIds)) . '</p>';
                foreach ($modules['modules'] as $module) {
                    echo $this->Form->input($module['name'], array('type' => 'checkbox', 'label' => h($module['name'])));
                    echo '<div class="clear"></div>';
                }
            } else {
                echo '<p>' . __('No expansion module is enabled, or the module system could not be reached.') . '</p>';
            }
            ?>
        </div>
    </fieldset>
        <div class="overlay_spacing" style="margin-top: 20px;">
            <table>
                <tr>
                <td style="vertical-align:top">
                    <?php if (!empty($modules['modules'])): ?>
                    <span id="submitButton" class="btn btn-primary" title="<?php echo __('Enrich'); ?>" role="button" tabindex="0" aria-label="<?php echo __('Enrich'); ?>" onClick="submitPopoverForm('<?php echo h($id); ?>', 'massEnrich')"><?php echo __('Enrich'); ?></span>
                    <?php endif; ?>
                </td>
                <td style="width:540px;">&nbsp;</td>
                <td style="vertical-align:top;">
                    <span class="btn btn-inverse" title="<?php echo __('Cancel'); ?>" role="button" tabindex="0" aria-label="<?php echo __('Cancel'); ?>" id="cancel_attribute_add"><?php echo __('Cancel'); ?></span>
                </td>
                </tr>
            </table>
        </div>
    <?php
        echo $this->Form->end();
    ?>
</div>

<script type="text/javascript">
$(function() {
    $('#cancel_attribute_add').click(function() {
        $('#gray_out').fadeOut();
        $('#popover_form').fadeOut();
    });
});
</script>
