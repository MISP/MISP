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
            'title' => _('The end of life of the indicator'),
            'type' => 'number',
            'min' => 0,
            'class' => 'form-control span6',
            'div' => 'input clear',
            'value' => $this->request->data['DecayingModel']['parameters']['tau']
        ));
        echo $this->Form->input('DecayingModel.parameters.delta', array(
            'label' => __('Delta parameter'),
            'title' => _('The decay speed of the indicator'),
            'type' => 'number',
            'min' => 0,
            'class' => 'form-control span6',
            'div' => 'input clear',
            'value' => $this->request->data['DecayingModel']['parameters']['delta']
        ));
        echo $this->Form->input('DecayingModel.parameters.threshold', array(
            'label' => __('Threshold parameter'),
            'title' => _('The model threshold of the indicator'),
            'type' => 'number',
            'min' => 0,
            'class' => 'form-control span6',
            'div' => 'input clear',
            'value' => $this->request->data['DecayingModel']['parameters']['threshold']
        ));
    ?>
        <div class="clear"></div>
    </fieldset>
<?php
    echo $this->Form->button(__('Edit'), array('class' => 'btn btn-primary'));
    echo $this->Form->end();
?>
</div>
<?php
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'decayingModel', 'menuItem' => 'edit'));
?>
