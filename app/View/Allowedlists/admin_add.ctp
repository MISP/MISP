<div class="allowedlist form">
<?php echo $this->Form->create('Allowedlist');?>
    <fieldset>
        <legend><?php echo __('Add Signature Allowedlist');?></legend>
    <?php
        echo $this->Form->input('name', array(
            'class' => 'input-xxlarge'
        ));

    ?>
    </fieldset>
<?php
echo $this->Form->button(__('Add'), array('class' => 'btn btn-primary'));
echo $this->Form->end();
?>
</div>
<?php
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'allowedlist', 'menuItem' => 'add'));
?>
