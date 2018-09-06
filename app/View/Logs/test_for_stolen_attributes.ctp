<div class="index">
    <h3><?php echo __('Stolen attribute validation');?></h3>
    <ul>
    <?php
    if (empty($issues)) {
      echo '<span class="blue bold">' . __('Nothing to see here, move along.') . '</span>';
    } else {
      foreach ($issues as $aid => $eids) {
        echo '<div>' . __('Attribute (%s) associated to events: %s', $aid, implode(', ', $eids)) . '</div>';
      }
    }
  ?>
</div>
<?php
    echo $this->element('side_menu', array('menuList' => 'admin', 'menuItem' => 'adminTools'));
?>
