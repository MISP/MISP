<div class="whitelist form">
<?php echo $this->Form->create('Whitelist');?>
    <fieldset>
        <legend><?php echo __('Add Signature Whitelist');?></legend>
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
    echo $this->element('side_menu', array('menuList' => 'whitelist', 'menuItem' => 'add'));
?>
