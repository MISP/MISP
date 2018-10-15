<div class="eventBlacklist form">
<?php echo $this->Form->create('EventBlacklist');?>
    <fieldset>
        <legend><?php echo __('Add Event Blacklist Entries');?></legend>
        <p><?php echo __('Simply paste a list of all the event UUIDs that you wish to block from being entered.');?></p>
    <?php
        echo $this->Form->input('event_orgc', array(
                'div' => 'input clear',
                'class' => 'input-xxlarge',
                'label' => __('Creating organisation'),
                'default' => $blockEntry['EventBlacklist']['event_orgc'],
        ));
        echo $this->Form->input('event_info', array(
                'type' => 'textarea',
                'div' => 'input clear',
                'class' => 'input-xxlarge',
                'label' => __('Event info'),
                'default' => $blockEntry['EventBlacklist']['event_info'],
        ));
        echo $this->Form->input('comment', array(
                'type' => 'textarea',
                'div' => 'input clear',
                'class' => 'input-xxlarge',
                'default' => $blockEntry['EventBlacklist']['comment'],
        ));
    ?>
    </fieldset>
<?php
echo $this->Form->button(__('Add'), array('class' => 'btn btn-primary'));
echo $this->Form->end();
?>
</div>
<?php
    echo $this->element('side_menu', array('menuList' => 'admin', 'menuItem' => 'eventBlacklistsAdd'));
?>
