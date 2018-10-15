<div class="events form">
<?php
  echo $this->Form->create('Event', array('type' => 'file'));
?>
<fieldset>
<legend><?php echo __('Import %s file', $stix_version); ?></legend>
<?php
    echo $this->Form->input('Event.stix', array(
            'label' => '<b>' . __('%s file', $stix_version) . '</b>',
            'type' => 'file',
    ));
?>
<div class="input clear"></div>
<?php
    echo $this->Form->input('publish', array(
            'checked' => false,
            'label' => __('Publish imported events'),
    ));
?>
<div class="input clear"></div>
<?php
    echo $this->Form->input('original_file', array(
            'checked' => true,
            'label' => __('Include the original imported file as attachment')
    ));
?>
</fieldset>
<?php
    echo $this->Form->button(__('Upload'), array('class' => 'btn btn-primary'));
    echo $this->Form->end();
?>
</div>
<?php
    echo $this->element('side_menu', array('menuList' => 'event-collection', 'menuItem' => 'addSTIX'));
?>
