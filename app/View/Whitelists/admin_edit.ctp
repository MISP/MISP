<div class="whitelist form">
<?php echo $this->Form->create('Whitelist');?>
    <fieldset>
        <legend><?php echo __('Edit Signature Whitelist');?></legend>
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
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'whitelist', 'menuItem' => 'edit', 'id' => $this->Form->value('Whitelist.id')));
?>
