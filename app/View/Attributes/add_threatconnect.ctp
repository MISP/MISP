<div class="attributes form">
<?php echo $this->Form->create('Attribute', array('enctype' => 'multipart/form-data'));?>
    <fieldset>
        <legend><?php echo __('Import ThreatConnect CSV file'); ?></legend>
        <?php
        echo $this->Form->hidden('event_id');
        ?>
        <div class="input clear"></div>
        <div class="input">
        <?php
        echo $this->Form->file('value', array(
            'error' => array('escape' => false),
        ));
        ?>
        </div>
    </fieldset>
<?php
echo $this->Form->button('Upload', array('class' => 'btn btn-primary'));
echo $this->Form->end();
?>
</div>
<?php
    $event['Event']['id'] = $this->request->data['Attribute']['event_id'];
    $event['Event']['published'] = $published;
    echo $this->element('side_menu', array('menuList' => 'event', 'menuItem' => 'addThreatConnect', 'event' => $event));
?>
