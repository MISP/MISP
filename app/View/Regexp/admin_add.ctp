<div class="regexp form">
<?php echo $this->Form->create('Regexp');?>
    <fieldset>
        <legend><?php echo __('Add Import Regexp');?></legend>
    <?php
        echo $this->Form->input('regexp');
        echo $this->Form->input('replacement');
    ?>
    <div class = "clear">
            <?php echo __('Types to be affected by the filter (Setting \'all\' will override the other settings)');?>
    </div>
                <br />
    <div class="input clear">
    <?php
        echo $this->Form->input('all', array(
            'checked' => false,
            'label' => 'All',
        ));
    ?>
    </div>
    <div class="input clear">   </div>
    <?php
        foreach ($types as $key => $type) {
            echo $this->Form->input($key, array(
                'checked' => false,
                'label' => $type,
            ));
        }
    ?>
    </fieldset>
<?php
echo $this->Form->button(__('Add'), array('class' => 'btn btn-primary'));
echo $this->Form->end();
?>
</div>
<?php
    echo $this->element('side_menu', array('menuList' => 'regexp', 'menuItem' => 'add'));
?>
