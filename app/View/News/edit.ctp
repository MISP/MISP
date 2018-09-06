<div class="news form">
<?php
    echo $this->Form->create('News');
?>
    <fieldset>
        <legend><?php echo __('Edit News Item'); ?></legend>
        <?php
            echo $this->Form->input('title', array(
                    'type' => 'text',
                    'error' => array('escape' => false),
                    'div' => 'input clear',
                    'class' => 'input-xxlarge'
            ));
            ?>
                <div class="input clear"></div>
            <?php
            echo $this->Form->input('message', array(
                    'type' => 'textarea',
                    'error' => array('escape' => false),
                    'div' => 'input clear',
                    'class' => 'input-xxlarge'
            ));
            ?>
            <div class="input clear"></div>
            <?php
            echo $this->Form->input('anonymise', array(
                        'type' => 'checkbox',
                        'checked' => $newsItem['News']['user_id'] == 0,
                        'label' => __('Create anonymously'),
            ));
        ?>
    </fieldset>
    <?php
        echo $this->Form->button(__('Submit'), array('class' => 'btn btn-primary'));
        echo $this->Form->end();
    ?>
</div>
<?php
    echo $this->element('side_menu', array('menuList' => 'news', 'menuItem' => 'edit'));
?>
