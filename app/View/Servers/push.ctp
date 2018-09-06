<div class="servers index">
    <h2><?php echo __('Failed pushes');?></h2>
    <?php
if (0 == count($fails)):?>
    <p><?php echo __('No failed pushes');?></p>
    <?php
else:?>
    <ul>
    <?php foreach ($fails as $key => $value) echo '<li>' . $key . ' : ' . h($value) . '</li>'; ?>
    </ul>
    <?php
endif;?>
    <h2><?php echo __('Succeeded pushes');?></h2>
    <?php
if (0 == count($successes)):?>
    <p><?php echo __('No succeeded pushes');?></p>
    <?php
else:?>
    <ul>
    <?php foreach ($successes as $success) echo '<li>' . $success . '</li>'; ?>
    </ul>
    <?php
endif;?>
</div>

<?php
    echo $this->element('side_menu', array('menuList' => 'sync', 'menuItem' => 'push'));
?>
