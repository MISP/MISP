<div class="posts form">
<?php echo $this->Form->create('Post');?>
    <fieldset>
        <legend><?php echo __('Edit Post');?></legend>
        <div class="input text">
            <label for="PostTitle"><?php echo __('Thread Subject');?></label>
            <input class = "input-xxlarge" disabled="disabled" value="<?php echo h($title);?>" id="PostTitle" type="text">
        </div>
    <?php
        echo $this->Form->input('contents', array(
                'type' => 'textarea',
                'div' => 'input clear',
                'class' => 'input-xxlarge',
                'default' => $contents
        ));
    ?>
    </fieldset>
<?php
echo $this->Form->button('Submit', array('class' => 'btn btn-primary'));
echo $this->Form->end();
?>
</div>
<?php
    echo $this->element('side_menu', array('menuList' => 'threads', 'menuItem' => 'edit'));
?>
