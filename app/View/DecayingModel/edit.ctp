<div class="form">
<?php echo $this->Form->create('DecayingModel');?>
    <fieldset>
        <legend><?php echo __('Add DecayingModel');?></legend>
    <?php
        echo $this->Form->input('name', array(
        ));
        echo $this->Form->input('description', array(
        ));
        echo $this->Form->input('parameters', array(
            "value" => isset($this->request->data['DecayingModel']['parameters']) ? json_encode($this->request->data['DecayingModel']['parameters'],  JSON_PRETTY_PRINT) : ''
        ));
    ?>
        <div class="clear"></div>
    </fieldset>
<?php
    echo $this->Form->button(__('Edit'), array('class' => 'btn btn-primary'));
    echo $this->Form->end();
?>
</div>
<?php
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'decayingModel', 'menuItem' => 'edit'));
?>
