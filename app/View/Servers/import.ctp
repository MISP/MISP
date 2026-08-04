<div class="feed form">
<?php echo $this->Form->create('Server');?>
    <fieldset>
        <legend><?php echo __('Paste server data');?></legend>
        <p><?php echo __('Paste a MISP server metadata JSON below to add sync connections.');?></p>
    <div>
    <?php
        echo $this->Form->input('json', array(
                'div' => 'input clear',
                'label' => __('JSON'),
                'placeholder' => __('Server metadata JSON'),
                'class' => 'form-control span6',
                'type' => 'textarea',
                'rows' => 18
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
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'sync', 'menuItem' => 'import'));
