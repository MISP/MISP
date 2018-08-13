<div class="event index">
    <h2><?php echo __('Listing invalid event validations');?></h2>
    <?php echo __('Events analysed: %s', $count);?><br />
    <?php
        foreach ($result as $r) {
            ?>
            <h3><?php echo __('Validation errors for event: %s', h($r['id']));?></h3>
            <?php print_r($r['error']); ?><br />
            <?php echo __('Attribute details');?>:<br />
                <?php print_r(h($r['details'])); ?>
            <br/>
    <?php
        }
    ?>
</div>
<?php
    echo $this->element('side_menu', array('menuList' => 'admin', 'menuItem' => 'adminTools'));
?>
