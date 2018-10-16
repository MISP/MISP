<div class="event index">
    <h2><?php echo __('Listing invalid attribute validations'); ?></h2>
    <?php
        foreach ($result as $r) {
            ?>
            <h3><?php echo __('Validation errors for attribute: ') . h($r['id']); ?></h3>
            <?php
                foreach ($r['error'] as $field => $error) {
                    // re-think i18n & l10n for the below line
                    echo '<b>[' . h($field) . ']</b>: ' . __('Value found: ') . h($error['value']) . ' - ' . __('Error') . ': ' . h($error['error']) . '<br />';
                }
            ?>
            <b><?php echo __('[Attribute details]'); ?></b>: <?php echo h($r['details']); ?><br/>
    <?php
        }
    ?>
</div>
<?php
echo $this->element('side_menu', array('menuList' => 'admin', 'menuItem' => 'adminTools'));
?>
