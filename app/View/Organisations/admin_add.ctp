<div class="organisations form">
<?php echo $this->Form->create('Organisation'); ?>
    <fieldset>
        <legend><?php echo __('Add Organisation'); ?></legend>
    <?php echo $this->Form->input('name', array('class' => 'input-xxlarge'));
    echo $this->Form->input('sharing_group_id', array('div' => 'clear'));
     ?>
    </fieldset>
<?php echo $this->Form->button(__('Submit'), array('class' => 'btn btn-primary')); ?>
<?php echo $this->Form->end(); ?>
</div>
<div class="actions">
    <h3><?php echo __('Actions'); ?></h3>
    <ul>
        <li><?php echo $this->Html->link(__('List Organisations'), array('action' => 'index')); ?></li>
    </ul>
</div>