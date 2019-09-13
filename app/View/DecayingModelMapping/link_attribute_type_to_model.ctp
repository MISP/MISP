<div class="form">
<?php echo $this->Form->create('DecayingModelMapping');?>
    <fieldset>
        <legend><?php echo __('Add DecayingModelMapping');?></legend>
    <?php
        echo $this->Form->input('model_id', array(
            'hidden' => true,
            'value' => $model_id
        ));
        echo $this->Form->input('attributetypes', array());
    ?>
        <div class="clear"></div>
    </fieldset>
<?php
    echo $this->Form->button(__('Add'), array('class' => 'btn btn-primary'));
    echo $this->Form->end();
?>
</div>
<?php
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'decayingModel', 'menuItem' => 'add'));
?>
