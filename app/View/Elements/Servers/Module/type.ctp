<?php
  $branches = array('services', 'timeout', 'hover');
?>
<div class="templateTableRow ui-sortable-handle">
    <div class="templateElementHeader" style="width:100%; position:relative;">
        <div class="templateGlass"></div>
        <div class="templateElementHeaderText"><?php echo h($type); ?></div>
    </div>
  <div style="padding:10px;">
    <div><?php echo h($moduleTypes[$type]['description']); ?></div>
    <div><span class="bold"><?php echo __('Status'); ?></span>: <span id="<?php echo h(strtolower($type)); ?>_type">&nbsp;</span></div>
    <?php
      foreach ($branches as $branch):
        if (isset($modules[$type][$branch])):
          if (isset($modules[$type][$branch]['value'])) {
            $modules[$type][$branch] = array($branch => $modules[$type][$branch]);
          }
          foreach ($modules[$type][$branch] as $setting => $data):
            if ($branch == 'hover') $setting = 'hover_' . $setting;
            if ($data['type'] == 'boolean') $data['value'] = $data['value'] ? 'Yes' : 'No';
        ?>
            <div><span class="bold"><?php echo $setting; ?></span>: <?php echo h($data['value']); ?></div>
        <?php
          endforeach;
        endif;
      endforeach;
      $moduleCounter = 0;
      $enabledModuleCounter = 0;
      if (!empty($modules[$type]['modules'])):
        foreach ($modules[$type]['modules'] as $moduleType => $moduleSettings):
          $moduleCounter++;
          if ($moduleSettings['enabled']['value']) $enabledModuleCounter++;
        endforeach;
      endif;
    ?>
  </div>
</div>
