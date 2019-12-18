<div class="roles form">
<?php echo $this->Form->create('TagCollection'); ?>
    <fieldset>
        <?php
            if ($action === 'add') {
                echo sprintf('<legend>%s</legend>', __('Add Tag Collection'));
            } else {
                echo sprintf('<legend>%s</legend>', __('Edit Tag Collection'));
            }
            echo $this->Form->input('name', array('class' => 'span6'));
            echo '<div class="input clear"></div>';
            echo $this->Form->input('description', array('class' => 'span6'));
            echo '<div class="input clear"></div>';
            echo $this->Form->input('all_orgs', array(
                'type' => 'checkbox',
                'label' => __('Visible to all orgs')
            ));
        ?>
    </fieldset>
<?php
echo $this->Form->button(__('Submit'), array('class' => 'btn btn-primary'));
echo $this->Form->end();
?>
</div>
<?php
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'tag-collections', 'menuItem' => 'add'));
?>
