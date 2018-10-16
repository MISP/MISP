<div class="events form">
<?php echo $this->Form->create('Event', array('type' => 'file'));?>
    <fieldset>
        <legend><?php echo __('Import from MISP Export File'); ?></legend>
<?php
    echo $this->Form->input('Event.submittedfile', array(
            'label' => '<b>' . __('MISP XML or JSON file') . '</b>',
            'type' => 'file',
    ));
    ?>
        <div class="input clear"></div>
    <?php
    if (Configure::read('MISP.take_ownership_xml_import')):
    echo $this->Form->input('Event.takeownership', array(
            'checked' => false,
            'label' => __('Take ownership of the event'),
            'title' => __('Warning: This will change the creator organisation of the event, tampering with the event\'s ownership and releasability and can lead to unexpected behaviour when synchronising the event with instances that have another creator for the same event.)'
    )));
    endif;
    echo $this->Form->input('publish', array(
            'checked' => false,
            'label' => __('Publish imported events'),
    ));
?>
    </fieldset>
<?php
    echo $this->Form->button(__('Upload'), array('class' => 'btn btn-primary'));
    echo $this->Form->end();
?>
</div>
<?php
    echo $this->element('side_menu', array('menuList' => 'event-collection', 'menuItem' => 'addMISPExport'));
?>
