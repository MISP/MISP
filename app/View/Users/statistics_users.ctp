<div class = "index">
  <h2><?php echo __('Statistics');?></h2>
  <?php
    echo $this->element('Users/statisticsMenu');
  ?>
  <h4><?php echo __('User and Organisation Statistics');?></h4>
  <div style="width:250px;">
    <dl>
    <?php
      foreach ($statistics as $type => $data) {
        foreach ($data['data'] as $time_frame => $count) {
          $extra = '';
          $icon = '';
          if ($count && $time_frame !== 'total') {
            $extra = 'green';
            $icon = '<span class="fa fa-angle-up"></span>';
          }
          echo sprintf('<dt>%s (%s)</dt>', Inflector::humanize(h($type)), Inflector::humanize(h($time_frame)));
          echo sprintf('<dd class="bold %s">%s %s</dd>', $extra, h($count), $icon);
        }
      }
    ?>
    </dl>
  </div>
</div>
<?php
    echo $this->element('side_menu', array('menuList' => 'globalActions', 'menuItem' => 'statistics'));
?>
