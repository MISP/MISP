<div class="events form">
<?php echo $this->Form->create('Event', array('type' => 'file'));?>
    <fieldset>
        <legend><?php echo __('Import OpenIOC'); ?></legend>
<?php
echo $this->Form->input('Event.submittedioc', array(
        'label' => '<b>OpenIOC</b>',
        'type' => 'file',
));
?>
    </fieldset>
<?php
echo $this->Form->button(__('Upload'), array('class' => 'btn btn-primary'));
echo $this->Form->end();
?>
</div>
<?php
    $event['Event']['id'] = $id;
    $event['Event']['uuid'] = $uuid;
    $event['Event']['published'] = $published;
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'event', 'menuItem' => 'addIOC', 'event' => $event));
?>
