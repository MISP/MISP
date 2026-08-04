<?php
/*
 * Post-run summary for /event_templates/update (POST). Renders the
 * five outcome categories from EventTemplate::updateFromLibrary
 * (PRD §5.3): installed / updated / skipped_current / skipped_forked /
 * failed.
 */
$installed = isset($summary['installed']) ? $summary['installed'] : array();
$updated = isset($summary['updated']) ? $summary['updated'] : array();
$skippedCurrent = isset($summary['skipped_current']) ? $summary['skipped_current'] : array();
$skippedForked = isset($summary['skipped_forked']) ? $summary['skipped_forked'] : array();
$failed = isset($summary['failed']) ? $summary['failed'] : array();

$totalChanged = count($installed) + count($updated);

$renderRows = function ($rows) use ($baseurl) {
    if (empty($rows)) {
        echo '<p><em>' . __('None.') . '</em></p>';
        return;
    }
    echo '<ul>';
    foreach ($rows as $r) {
        $hasId = isset($r['id']) && (int)$r['id'] > 0;
        printf(
            '<li>%s — <code>%s</code></li>',
            $hasId
                ? sprintf(
                    '<a href="%s">%s</a>',
                    h($baseurl . '/event_templates/view/' . (int)$r['id']),
                    h($r['name'] ?? '')
                )
                : h($r['name'] ?? ''),
            h($r['slug'] ?? '')
        );
    }
    echo '</ul>';
};
?>
<div class="eventTemplates update">
    <h2><?php echo __('Library update — Event Templates'); ?></h2>

    <?php if ($totalChanged === 0 && empty($failed)): ?>
        <div class="alert alert-info">
            <?php echo __('Nothing to do — every library template is already current locally.'); ?>
        </div>
    <?php else: ?>
        <p>
            <?php echo __('Walked the bundled <code>misp-event-templates</code> submodule and reconciled it with this instance. Summary:'); ?>
        </p>
    <?php endif; ?>

    <h3>
        <?php echo __('Installed'); ?>
        <span class="muted">(<?php echo count($installed); ?>)</span>
    </h3>
    <?php $renderRows($installed); ?>
    <?php if (!empty($installed)): ?>
        <p class="muted" style="font-size:12px;">
            <?php echo __('New rows are <code>active = 0</code> by default — flip the active flag on each row before your team uses them.'); ?>
        </p>
    <?php endif; ?>

    <h3>
        <?php echo __('Updated'); ?>
        <span class="muted">(<?php echo count($updated); ?>)</span>
    </h3>
    <?php $renderRows($updated); ?>
    <?php if (!empty($updated)): ?>
        <p class="muted" style="font-size:12px;">
            <?php echo __('Existing rows whose upstream content changed. Local id, ownership, and active flag preserved.'); ?>
        </p>
    <?php endif; ?>

    <h3>
        <?php echo __('Already current'); ?>
        <span class="muted">(<?php echo count($skippedCurrent); ?>)</span>
    </h3>
    <?php $renderRows($skippedCurrent); ?>

    <h3>
        <?php echo __('Skipped (forked)'); ?>
        <span class="muted">(<?php echo count($skippedForked); ?>)</span>
    </h3>
    <?php $renderRows($skippedForked); ?>
    <?php if (!empty($skippedForked)): ?>
        <p class="muted" style="font-size:12px;">
            <?php echo __('Rows where you flipped <code>misp_default</code> off. Library updates leave these alone. Flip the flag back to opt back into upstream updates.'); ?>
        </p>
    <?php endif; ?>

    <?php if (!empty($failed)): ?>
        <h3 style="color:#c33;">
            <?php echo __('Failed'); ?>
            <span class="muted">(<?php echo count($failed); ?>)</span>
        </h3>
        <ul>
            <?php foreach ($failed as $f): ?>
                <li>
                    <code><?php echo h($f['slug'] ?? '(no slug)'); ?></code>
                    — <?php echo h($f['error']); ?>
                </li>
            <?php endforeach; ?>
        </ul>
    <?php endif; ?>

    <p style="margin-top:14px;">
        <a href="<?php echo h($baseurl . '/event_templates/index'); ?>" class="btn btn-primary">
            <?php echo __('Back to event templates'); ?>
        </a>
    </p>
</div>
<?php
echo $this->element('/genericElements/SideMenu/side_menu', array(
    'menuList' => 'eventTemplates',
    'menuItem' => 'update',
));
?>
