<?php
/*
 * Phase 2.4 placeholder — Phase 3.1 will replace this with a proper
 * styled summary view (installed / updated / skipped sections + copy
 * explaining the `default` flag mechanic). For now we just dump the
 * summary so the HTML branch does not 500 while the loader is wired up.
 */
?>
<div class="eventTemplates update">
    <h2><?php echo __('Library update — Event Templates'); ?></h2>
    <p>
        <?php echo __('Walked the bundled misp-event-templates submodule and reconciled with this instance.'); ?>
    </p>
    <pre style="max-height:600px;overflow:auto;background:#f8f8f8;border:1px solid #ddd;padding:10px;">
<?php echo h(JsonTool::encode($summary, true)); ?>
    </pre>
    <p>
        <a href="<?php echo h($baseurl . '/event_templates/index'); ?>" class="btn btn-primary">
            <?php echo __('Back to event templates'); ?>
        </a>
    </p>
</div>
<?php
echo $this->element('/genericElements/SideMenu/side_menu', array(
    'menuList' => 'eventTemplates',
    'menuItem' => 'index',
));
?>
