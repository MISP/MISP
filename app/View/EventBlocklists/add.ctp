<div class="eventBlocklist form">
<?php echo $this->Form->create('EventBlocklist');?>
    <fieldset>
        <legend><?php echo __('Add Event Blocklist Entries');?></legend>
        <p><?php echo __('Simply paste a list of all the event UUIDs that you wish to block from being entered.');?></p>
    <?php
        echo $this->Form->input('uuids', array(
                'type' => 'textarea',
                'label' => __('UUIDs'),
                'div' => 'input clear',
                'class' => 'input-xxlarge',
                'placeholder' => __('Enter a single or a list of UUIDs')
        ));
        echo $this->Form->input('event_orgc', array(
                'div' => 'input clear',
                'class' => 'input-xxlarge',
                'label' => 'Creating organisation',
                'placeholder' => __('(Optional) The organisation that the event is associated with')
        ));
        echo $this->Form->input('event_info', array(
                'type' => 'textarea',
                'div' => 'input clear',
                'class' => 'input-xxlarge',
                'label' => __('Event info'),
                'placeholder' => __('(Optional) the event info of the event that you would like to block. It\'s best to leave this empty if you are adding a list of UUIDs.')
        ));
        echo $this->Form->input('comment', array(
                'type' => 'textarea',
                'div' => 'input clear',
                'class' => 'input-xxlarge',
                'placeholder' => __('(Optional) Any comments you would like to add regarding this (or these) entries.')
        ));
    ?>
    </fieldset>
<?php
echo $this->Form->button(__('Add'), array('class' => 'btn btn-primary'));
echo $this->Form->end();
?>
</div>
<?php
    if ($isSiteAdmin) {
        echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'admin', 'menuItem' => 'eventBlocklistsAdd'));
    } else {
        echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'event-collection', 'menuItem' => 'eventBlocklistsAdd'));
    }
?>
