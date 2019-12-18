<div class="tag_collection form">
<?php echo $this->Form->create('TagCollection');?>
    <fieldset>
        <legend><?php echo __('Paste tag collection data');?></legend>
        <p><?php echo __('Paste a MISP tag collection JSON below to add tag collections.');?></p>
    <div>
    <?php
        echo $this->Form->input('json', array(
                'div' => 'input clear',
                'label' => __('JSON'),
                'placeholder' => __('Tag collection JSON'),
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
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'tag-collections', 'menuItem' => 'import'));
