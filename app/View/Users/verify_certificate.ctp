<div class="index">
    <h3><?php echo __('Certificates validation');?></h3>
    <ul>
    <?php foreach ($users as $k => $user) {
        echo $k . ' (' . $user[1] . '):<br />';
        if (isset($user[0])) {
            echo '-> <span style="color:red;">Invalid.</span><br />';
        } else {
            echo '-> <span style="color:green;">OK</span><br />';
        }
        echo '------------------------------------------------------------------------------<br />';
    }
    ?>
    </ul>
</div>
<?php
    echo $this->element('side_menu', array('menuList' => 'admin', 'menuItem' => 'adminTools'));
