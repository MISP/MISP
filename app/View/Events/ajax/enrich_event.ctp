<div class="confirmation">
  <legend><?php echo __('Enrich Event'); ?></legend>
  <div style="padding-left:5px;padding-right:5px;padding-bottom:5px;">
  <p><?php echo __('Select the enrichments you wish to run');?></p>
<?php
  echo $this->Form->create('', array('style' => 'margin-bottom:0px;'));
  foreach ($modules['modules'] as $module) {
    echo $this->Form->input($module['name'], array('type' => 'checkbox', 'label' => h($module['name'])));
  }
?>
<table>
  <tr>
    <td style="vertical-align:top">
      <?php
        echo $this->Form->submit('Enrich', array('class' => 'btn btn-primary'));
      ?>
    </td>
    <td style="width:540px;">
    </td>
    <td style="vertical-align:top;">
      <span role="button" tabindex="0" aria-label="<?php echo __('Cancel');?>" title="<?php echo __('Cancel');?>" class="btn btn-inverse" id="PromptNoButton" onClick="cancelPrompt();"><?php echo __('Cancel');?></span>
    </td>
  </tr>
</table>
<?php
  echo $this->Form->end();
?>
</div>
</div>
<script type="text/javascript">
    $(document).ready(function() {
        resizePopoverBody();
    });

    $(window).resize(function() {
        resizePopoverBody();
    });
</script>
