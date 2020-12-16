<div class="events form">
<?php echo $this->Form->create('Event');?>
    <fieldset>
        <legend><?= __('Contact organization reporting event %s', h($event['Event']['id'])) ?></legend>
        <p><?= __('You are about to contact the organization %s that reported event %s.<br>
                Feel free to add a custom message that will be sent to the reporting organization.<br>
                Your email address and details about the event will be added automagically to the message.', h($event['Orgc']['name']), h($event['Event']['info']));?></p>
    <?php
        echo $this->Form->input('message', array(
            'type' => 'textarea',
            'class' => 'input-xxlarge',
        ));
    ?>
        <div class="input clear"></div>
    <?php
        echo $this->Form->input('person', array(
            'label' => __('Submit only to the person that created the event'),
            'type' => 'checkbox',
            'class' => 'clear',
            // 'after' => $this->Html->div('forminfo', __('By selecting this box you will contact the creator of the event only.', true)),
        ));
    ?>
        <div class="input clear">
    <?php
        echo $this->Form->button(__('Submit'), array('class' => 'btn btn-primary'));
        echo $this->Form->end();
    ?>
        </div>
    </fieldset>
</div>
<?= $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'event', 'menuItem' => 'contact', 'event' => $event));
