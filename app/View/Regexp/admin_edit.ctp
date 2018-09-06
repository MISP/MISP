<div class="regexp form">
<?php echo $this->Form->create('Regexp');?>
    <fieldset>
        <legend><?php echo __('Edit Import Regexp');?></legend>
    <?php
        echo $this->Form->input('id');
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
            'checked' => $all,
            'label' => __('All'),
        ));
    ?>
    </div>
    <div class="input clear">   </div>
    <?php
        if ($all) {
            foreach ($types as $key => $type) {
                echo $this->Form->input($key, array(
                'checked' => $value[$key],
                'label' => $type,
                ));
            }
        } else {
            foreach ($types as $key => $type) {
                echo $this->Form->input($key, array(
                    'checked' => $value[$key],
                    'label' => $type,
                ));
            }
        }
    ?>
    </fieldset>
<?php
echo $this->Form->button(__('Add'), array('class' => 'btn btn-primary'));
echo $this->Form->end();
?>
</div>
<?php
    echo $this->element('side_menu', array('menuList' => 'regexp', 'menuItem' => 'edit', 'id' => $this->Form->value('Regexp.id')));
?>
