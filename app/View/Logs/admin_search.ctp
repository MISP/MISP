<div class="logs form">
<?php echo $this->Form->create('Log', array('novalidate'=>true, 'url' => $baseurl . '/logs/admin_search/search'));?>
    <fieldset>
        <legend><?php echo __('Search Logs');?></legend>
    <?php
        echo $this->Form->input('email', array( 'label' => __('Email')));
        if ($orgRestriction == false) {
            echo $this->Form->input('org', array( 'label' => __('Organisation')));
        }
        if (Configure::read('MISP.log_client_ip')) echo $this->Form->input('ip', array( 'label' => 'IP'));
        echo $this->Form->input('model', array(
                'between' => $this->Html->div('forminfo', '', array('id' => 'LogModelDiv')),
                'div' => 'input clear'));
        echo $this->Form->input('model_id', array('between' => $this->Html->div('forminfo', '', array('id' => 'LogModelIdDiv')),'type' => 'text', 'label' => __('Model ID')));
        echo $this->Form->input('action', array(
                'between' => $this->Html->div('forminfo', '', array('id' => 'LogActionDiv')),
        ));
        echo $this->Form->input('title', array(
                'label' => __('Title'),
                'div' => 'input clear'));
        echo $this->Form->input('change', array('label' => __('Change')));
        echo '<div class="input clear">';
        echo $this->Form->input('from', array('label' => __('From'), 'class' => 'datepicker form-control'));
        echo $this->Form->input('to', array('label' => __('To'), 'class' => 'datepicker form-control'));
        echo '<div class="input clear">';
        echo $this->Form->input(
            'from_time',
            [
                'label' => __('From time (requires from)'),
                'placeholder' => __("HH:MM:SS")
            ]
        );
        echo $this->Form->input(
            'to_time',
            [
                'label' => __('To time (requires to)'),
                'placeholder' => __("HH:MM:SS")
            ]
        );
    ?>
    </fieldset>
<?php
echo $this->Form->button(__('Search'), array('class' => 'btn btn-primary'));
echo $this->Form->end();
?>
</div>
<?php
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'logs', 'menuItem' => 'search'));
?>
