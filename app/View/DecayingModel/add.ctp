<div class="form">
<?php echo $this->Form->create('DecayingModel');?>
    <fieldset>
        <legend><?php echo __('Add DecayingModel');?></legend>
    <?php
        echo $this->Form->input('name', array(
        ));
        echo $this->Form->input('description', array(
        ));
        echo $this->Form->input('parameters', array(
        ));
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
