<div class="form">
<?php echo $this->Form->create('DecayingModel', array('enctype' => 'multipart/form-data'));?>
    <fieldset>
        <legend><?php echo __('Import model data');?></legend>
        <p><?php echo __('Paste a MISP model JSON or provide a JSON file below to add models.');?></p>
    <div>
    <?php
        echo $this->Form->input('json', array(
                'div' => 'input clear',
                'label' => __('JSON'),
                'placeholder' => __('Model JSON'),
                'class' => 'form-control span6',
                'type' => 'textarea',
                'rows' => 18
        ));
        echo $this->Form->input('submittedjson', array(
            'div' => 'input clear',
            'label' => __('JSON file'),
            'type' => 'file'
        ));
    ?>
    </div>
    </fieldset>
    <?php
        echo $this->Form->button(__('Add'), array('class' => 'btn btn-primary'));
        echo $this->Form->end();
    ?>
</div>
<?php
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'decayingModel', 'menuItem' => 'import'));
