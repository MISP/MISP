<?php
    echo sprintf(
        '<div class="index"><h4>%s</h4>%s</div>',
        __('Server configuration'),
        sprintf(
            '<pre style="width:600px;">%s</pre>',
            json_encode($server, JSON_PRETTY_PRINT)
        )
    );
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'sync', 'menuItem' => 'createSync'));
?>
