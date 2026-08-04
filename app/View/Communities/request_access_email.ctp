<div class="communities view">
    <?php
        echo sprintf(
            '<h3>%s</h3><p>%s</p><b>%s</b><p>%s</p><b>%s</b><p>%s</p>',
            __('Email to send in order to request access'),
            empty($mock) ? __('Emailing is currently disabled on the instance, but we have generated the e-mail that would normally be sent out below.') :
            __('Please find a generated e-mail below that you can use to contact the community in question'),
            __('Headers:'),
            nl2br(h($result['headers'])),
            __('Message:'),
            nl2br(h($result['message']))
        );
    ?>
</div>
<?php
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'sync', 'menuItem' => 'view_email'));
?>
