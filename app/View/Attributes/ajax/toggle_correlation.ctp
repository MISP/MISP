<div class="confirmation">
    <?php
    echo $this->Form->create('Attribute', array('style' => 'margin:0px;', 'id' => 'PromptForm', 'url' => '/attributes/toggleCorrelation/' . $attribute['Attribute']['id']));
    $extraTitle = "";
    ?>
    <legend><?php echo __('Toggle Correlation %s ', $attribute['Attribute']['disable_correlation'] ? __('on') : __('off'));?></legend>
    <div style="padding-left:5px;padding-right:5px;padding-bottom:5px;">
        <p>
    <?php
        if ($attribute['Attribute']['disable_correlation']) {
            echo __('Re-enable the correlation for this attribute.');
        } else {
            echo __('This will remove all correlations that already exist for this attribute and prevents any attributes to be related as long as this setting is disabled. Make sure you understand the downsides of disabling correlations.');
        }
    ?>
    </p>
        <table>
            <tr>
                <td style="vertical-align:top">
                    <span id="PromptYesButton" title="<?php echo __('Toggle correlation for attribute'); ?>" role="button" tabindex="0" aria-label="<?php echo __('Toggle correlation for attribute'); ?>" class="btn btn-primary" onClick="toggleCorrelation(<?php echo h($attribute['Attribute']['id']); ?>);"><?php echo __('Yes'); ?></span>
                </td>
                <td style="width:540px;">
                </td>
                <td style="vertical-align:top;">
                    <span class="btn btn-inverse" title="<?php echo __('Cancel'); ?>" role="button" tabindex="0" aria-label="<?php echo __('Cancel'); ?>" id="PromptNoButton" onClick="cancelPrompt();"><?php echo __('No'); ?></span>
                </td>
            </tr>
        </table>
    </div>
    <?php
        echo $this->Form->end();
    ?>
</div>
