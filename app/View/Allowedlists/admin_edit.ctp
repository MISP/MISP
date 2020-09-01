<div class="allowedlist form">
<?php echo $this->Form->create('Allowedlist');?>
    <fieldset>
        <legend><?php echo __('Edit Signature Allowedlist');?></legend>
    <?php
        echo $this->Form->input('id');
        echo $this->Form->input('name', array(
            'class' => 'input-xxlarge'
        ));
    ?>
    </fieldset>
<?php
    echo $this->Form->button(__('Submit'), array('class' => 'btn btn-primary'));
    echo $this->Form->end();
?>
</div>
<?php
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'allowedlist', 'menuItem' => 'edit', 'id' => $this->Form->value('Allowedlist.id')));
?>
