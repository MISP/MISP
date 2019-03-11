<div class="form">
<?php echo $this->Form->create('DecayingModel');?>
    <fieldset>
        <legend><?php echo __('Add DecayingModel');?></legend>
    <?php
        echo $this->Form->input('name', array(
        ));
        echo $this->Form->input('description', array(
        ));
        echo $this->Form->input('DecayingModel.parameters.tau', array(
            'label' => __('Tau parameter'),
            'type' => 'number',
            'min' => 0,
            'title' => _('The end of life of the indicator'),
            'class' => 'form-control span6',
            'div' => 'input clear',
        ));
        echo $this->Form->input('DecayingModel.parameters.delta', array(
            'label' => __('Delta parameter'),
            'type' => 'number',
            'min' => 0,
            'title' => _('The decay speed of the indicator'),
            'class' => 'form-control span6',
            'div' => 'input clear',
        ));
        echo $this->Form->input('DecayingModel.parameters.threshold', array(
            'label' => __('Threshold parameter'),
            'type' => 'number',
            'min' => 0,
            'title' => _('The model threshold of the indicator'),
            'class' => 'form-control span6',
            'div' => 'input clear',
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
