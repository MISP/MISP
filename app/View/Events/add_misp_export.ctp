<div class="events form">
<?php echo $this->Form->create('Event', array('type' => 'file'));?>
    <fieldset>
        <legend><?php echo __('Import from MISP Export File'); ?></legend>
<?php
    echo $this->Form->input('Event.filecontent', [
        'label' => 'Paste <b>' . __('MISP XML or JSON file content') . '</b>',
        'type' => 'textarea',
        'class' => 'span7',
    ]);
    echo '<div class="input clear"></div>';
    echo $this->Form->input('Event.submittedfile', array(
        'label' => 'or choose <b>' . __('MISP XML or JSON file') . '</b>',
        'type' => 'file',
    ));
    ?>
        <div class="input clear"></div>
    <?php
    if (Configure::read('MISP.take_ownership_xml_import')) {
        echo $this->Form->input('Event.takeownership', array(
            'checked' => false,
            'label' => __('Take ownership of the event'),
            'title' => __('Warning: This will change the creator organisation of the event, tampering with the event\'s ownership and releasability and can lead to unexpected behaviour when synchronising the event with instances that have another creator for the same event.')
        ));
    }
    if ($isAclPublish) {
        echo $this->Form->input('publish', array(
            'checked' => false,
            'label' => __('Publish imported events'),
        ));
    }
    ?>
        <div class="input clear"></div>
    <?php
    echo $this->Form->input('Event.signature', [
        'label' => __('Protected event signature - paste the b64 encoded key here if applicable.'),
        'type' => 'textarea',
        'class' => 'span7',
    ]);
    if (!empty(Configure::read('MISP.allow_users_override_locked_field_when_importing_events'))) {
        echo '<div class="input clear"></div>';
        echo $this->Form->input('allow_lock_override', array(
            'checked' => false,
            'label' => __('Allow lock override (locked state will be set based on the value defined in the imported events)'),
        ));
    }
?>
    </fieldset>
<?php
    echo $this->Form->button(__('Upload'), array('class' => 'btn btn-primary'));
    echo $this->Form->end();
?>
</div>
<?= $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'event-collection', 'menuItem' => 'import_from'));
