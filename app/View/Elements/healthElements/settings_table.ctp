<table class="table table-hover table-condensed settingsTableContainer">
    <tr class="subGroup_<?php echo h($subGroup);?> hidden">
            <th><?php echo __('Priority'); ?></th>
            <th><?php echo __('Setting'); ?></th>
            <th><?php echo __('Value'); ?></th>
            <th><?php echo __('Description'); ?></th>
            <th><?php echo __('Error Message'); ?></th>
    </tr>
    <?php
        foreach ($settings as $k => $setting) {
            echo $this->element('healthElements/settings_row', array('setting' => $setting, 'subGroup' => $subGroup, 'k' => $k));
        }
    ?>
</table>
