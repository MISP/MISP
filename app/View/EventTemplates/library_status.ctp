<?php
/*
 * Phase 2.4 placeholder — Phase 3.1 will replace with a proper status
 * view. JSON dump for now.
 */
?>
<div class="eventTemplates library_status">
    <h2><?php echo __('Library status — Event Templates'); ?></h2>
    <p>
        <?php echo __('Dry-run snapshot of the bundled misp-event-templates submodule and the local DB state. No writes.'); ?>
    </p>
    <pre style="max-height:600px;overflow:auto;background:#f8f8f8;border:1px solid #ddd;padding:10px;">
<?php echo h(JsonTool::encode($summary, true)); ?>
    </pre>
</div>
<?php
echo $this->element('/genericElements/SideMenu/side_menu', array(
    'menuList' => 'eventTemplates',
    'menuItem' => 'index',
));
?>
