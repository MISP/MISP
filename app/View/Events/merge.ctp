<div class="eventmerge form">
<?php echo $this->Form->create('Event', array('enctype' => 'multipart/form-data'));?>
    <fieldset>
        <legend><?php echo __('Merge events'); ?></legend>
        <?php
        echo $this->Form->hidden('target_id');
        echo $this->Form->input('source_id', array(
                'type' => 'text',
                'label' => __('Event id to copy the attributes from'),
                'error' => array('escape' => false),
                'div' => 'input clear',
                'class' => 'input'
        ));
        ?>
        <div class="input clear"></div>
        <?php
        echo $this->Form->input('to_ids', array(
                'type' => 'checkbox',
                'checked' => false,
                'label' => __('copy only IDS attributes'),
        ));
        ?>

    </fieldset>
<?php
echo $this->Form->button('Merge', array('class' => 'btn btn-primary'));
echo $this->Form->end();
?>
</div>
<?php
    $event['Event']['id'] = $this->request->data['Event']['target_id'];
    echo $this->element('side_menu', array('menuList' => 'event', 'menuItem' => 'merge', 'event' => $event));
?>
