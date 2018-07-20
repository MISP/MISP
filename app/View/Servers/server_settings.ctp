<div class="server index">
    <?php if ($writeableFiles[APP . 'Config/config.php'] != 0): ?>
    <div class="bold" style="background-color:red;width:100%;color:white;"><span style="padding-left:10px;"><?php echo __('Warning: app/Config/config.php is not writeable. This means that any setting changes made here will NOT be saved.');?></span></div>
    <?php endif; ?>
    <h2><?php echo __('Server Settings & Maintenance');?></h2>
    <?php
        echo $this->element('healthElements/tabs');
        if (in_array($tab, array('MISP', 'Security', 'Encryption', 'Proxy', 'Plugin'))) {
            echo $this->element('healthElements/settings_tab');
        } else if ($tab == 'diagnostics') {
            echo $this->element('healthElements/diagnostics');
        } else if ($tab == 'workers') {
            echo $this->element('healthElements/workers');
        } else if ($tab == 'files') {
            echo $this->element('healthElements/files');
        } else {
            echo $this->element('healthElements/overview');
        }
    ?>
    <div style="font-style: italic;"><?php echo __('To edit a setting, simply double click it.');?></div>
</div>
<?php
    echo $this->element('side_menu', array('menuList' => 'admin', 'menuItem' => 'serverSettings'));
?>
