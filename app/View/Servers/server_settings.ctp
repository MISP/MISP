<div class="server index">
    <?php if ($writeableFiles[APP . 'Config/config.php'] != 0 && !Configure::read('MISP.system_setting_db')): ?>
    <div class="alert alert-error"><?= __('Warning: app/Config/config.php is not writeable. This means that any setting changes made here will NOT be saved.') ?></div>
    <?php endif; ?>
    <h2><?php echo __('Server Settings & Maintenance');?></h2>
    <?php
        echo $this->element('healthElements/tabs', array('active_tab' => $tab));
        if (in_array($tab, ['MISP', 'Security', 'Encryption', 'Proxy', 'Plugin', 'SimpleBackgroundJobs'], true)) {
            echo $this->element('healthElements/settings_tab');
        } else if ($tab === 'diagnostics') {
            echo $this->element('healthElements/diagnostics');
        } else if ($tab === 'workers') {
            echo $this->element('healthElements/workers');
        } else if ($tab === 'files') {
            echo $this->element('healthElements/files');
        } else {
            echo $this->element('healthElements/overview');
        }
    ?>
    <div style="font-style: italic;"><?php echo __('To edit a setting, simply double click it.');?></div>
</div>
<script type="text/javascript">
    $(function() {
        $('#liveFilterField').focus().keyup(function() {
            liveFilter();
        });
    });

</script>
<?= $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'admin', 'menuItem' => 'serverSettings'));
