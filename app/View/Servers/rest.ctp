<div class="servers form">
<?php echo $this->Form->create('Server');?>
    <fieldset>
        <legend><?php echo __('REST client');?></legend>
    <?php
        echo $this->Form->input('method', array(
            'label' => __('Relative path to query'),
            'options' => array(
                'GET' => 'GET',
                'POST' => 'POST'
            )
        ));
        ?>
            <div class="input clear" style="width:100%;">
    <?php
        echo $this->Form->input('url', array(
            'label' => __('Relative path to query'),
            'class' => 'input-xxlarge'
        ));
    ?>
        <div class="input clear" style="width:100%;">
    <?php
        echo $this->Form->input('show_result', array(
            'type' => 'checkbox'
        ));
    ?>
        <div class="input clear" style="width:100%;">
    <?php
        echo $this->Form->input('header', array(
                'type' => 'textarea',
                'div' => 'input clear',
                'class' => 'input-xxlarge',
                'default' => !empty($this->request->data['Server']['header']) ? $this->request->data['Server']['header'] : $header
        ));
    ?>
        <div class="input clear" style="width:100%;">
    <?php
        echo $this->Form->input('body', array(
                'type' => 'textarea',
                'div' => 'input clear',
                'class' => 'input-xxlarge'
        ));
    ?>
        <div class="input clear" style="width:100%;">
    <?php
        echo $this->Form->submit('Run query', array('class' => 'btn btn-primary'));
        echo $this->Form->end();
    ?>
        <hr />
    </fieldset>
    <?php
        if (!empty($data['data'])) {
            echo sprintf('<h3>%s</h3>', __('Response'));
            echo sprintf('<div><span class="bold">%s</span>: %d</div>', __('Response code'), h($data['code']));
            echo sprintf('<div><span class="bold">%s</span>: %s</div>', __('Request duration'), h($data['duration']));
            echo sprintf('<div class="bold">%s</div>', __('Headers'));
            foreach ($data['headers'] as $header => $value) {
                echo sprintf('&nbsp;&nbsp;<span class="bold">%s</span>: %s<br />', h($header), h($value));
            }
            echo sprintf('<pre>%s</pre>', h($data['data']));
        }
    ?>
</div>
<?php
    echo $this->element('side_menu', array('menuList' => 'event-collection', 'menuItem' => 'rest'));
?>
