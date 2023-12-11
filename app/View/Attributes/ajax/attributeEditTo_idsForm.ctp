<div class="confirmation">
    <?php
    echo $this->Form->create('Attribute', array('style' => 'margin:0px;', 'id' => 'PromptForm', 'url' => $baseurl . '/attributes/editField/' . $object['id']));
    echo $this->Form->input('to_ids', array(
        'options' => array(0 => 'No', 1 => 'Yes'),
        'label' => false,
        'selected' => !$object['to_ids'],
        'class' => 'hidden',
        'id' => 'Attribute' . '_' . $object['id'] . '_to_ids_field',
        'div' => false
    ));
    ?>
    <legend><?php echo __('Toggle IDS flag %s ', !$object['to_ids'] ? __('on') : __('off'));?></legend>
    <div style="padding-left:5px;padding-right:5px;padding-bottom:5px;">
        <p>
    <?php
        if (!$object['to_ids']) {
            echo __('Set the IDS flag for this attribute.');
        } else {
            echo __('Unset the IDS flag for this attribute.');
        }
    ?>
    </p>
        <table>
            <tr>
                <td style="vertical-align:top">

                    <span id="PromptYesButton" title="<?php echo __('Toggle IDS flag for attribute'); ?>" role="button" tabindex="0" aria-label="<?php echo __('Toggle IDS flag for attribute'); ?>" class="btn btn-primary" onClick="toggleToIDS(<?php echo h($object['id']); ?>, 1);"><?php echo __('Yes'); ?></span>
                </td>
                <td style="width:540px;">
                </td>
                <td style="vertical-align:top;">
                    <span class="btn btn-inverse" title="<?php echo __('Cancel'); ?>" role="button" tabindex="0" aria-label="<?php echo __('Cancel'); ?>" id="PromptNoButton" onClick="cancelPrompt();"><?php echo __('No'); ?></span>
                </td>
            </tr>
        </table>
    </div>
    <?php echo $this->Form->end(); ?>
</div>
