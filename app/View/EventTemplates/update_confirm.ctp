<?php
/*
 * Confirm page for /event_templates/update (GET). Shows a dry-run
 * snapshot so the operator sees what the run will install vs touch
 * vs skip, then a form posts back to the same URL to execute.
 *
 * `$preview` shape matches `library_status` (PRD §5.3):
 *   {
 *     present_in_library: [
 *       { slug, uuid, name, local: null | { id, active, misp_default } }
 *     ],
 *     failed: [ { slug, error } ]
 *   }
 */
$present = isset($preview['present_in_library']) ? $preview['present_in_library'] : array();
$failed = isset($preview['failed']) ? $preview['failed'] : array();

// Bucket each entry by its anticipated outcome on update.
$buckets = array('install' => array(), 'managed' => array(), 'forked' => array());
foreach ($present as $row) {
    if (empty($row['local'])) {
        $buckets['install'][] = $row;
    } elseif ((int)$row['local']['misp_default'] === 1) {
        $buckets['managed'][] = $row;
    } else {
        $buckets['forked'][] = $row;
    }
}
?>
<div class="eventTemplates update_confirm">
    <h2><?php echo __('Update event templates from library'); ?></h2>

    <p>
        <?php echo __('This walks the bundled <code>misp-event-templates</code> submodule and reconciles its content with the local <code>event_templates</code> table.'); ?>
    </p>
    <p>
        <strong><?php echo __('Effect:'); ?></strong>
        <?php echo __('rows that are missing locally are <em>installed</em>; rows already present and library-managed (<code>misp_default = 1</code>) are <em>updated</em> if upstream content differs; rows the operator has explicitly forked (<code>misp_default = 0</code>) are <em>skipped</em>.'); ?>
    </p>

    <?php if (!empty($failed)): ?>
        <div class="alert alert-error">
            <strong><?php echo __('%d on-disk template(s) could not be parsed:', count($failed)); ?></strong>
            <ul style="margin:6px 0 0 20px;">
                <?php foreach ($failed as $f): ?>
                    <li><code><?php echo h($f['slug'] ?? '(no slug)'); ?></code> — <?php echo h($f['error']); ?></li>
                <?php endforeach; ?>
            </ul>
        </div>
    <?php endif; ?>

    <h3><?php echo __('Will install'); ?> <span class="muted">(<?php echo count($buckets['install']); ?>)</span></h3>
    <?php if (empty($buckets['install'])): ?>
        <p><em><?php echo __('Nothing to install — every library template already exists locally.'); ?></em></p>
    <?php else: ?>
        <ul>
            <?php foreach ($buckets['install'] as $r): ?>
                <li>
                    <code><?php echo h($r['slug']); ?></code> — <?php echo h($r['name']); ?>
                </li>
            <?php endforeach; ?>
        </ul>
        <p class="muted" style="font-size:12px;">
            <?php echo __('New rows will be created with <code>active = 0</code> and <code>distribution = 1</code> (community). Flip the active flag per row to expose them to your team.'); ?>
        </p>
    <?php endif; ?>

    <h3><?php echo __('May update'); ?> <span class="muted">(<?php echo count($buckets['managed']); ?>)</span></h3>
    <?php if (empty($buckets['managed'])): ?>
        <p><em><?php echo __('No library-managed rows installed yet.'); ?></em></p>
    <?php else: ?>
        <ul>
            <?php foreach ($buckets['managed'] as $r): ?>
                <li>
                    <a href="<?php echo h($baseurl . '/event_templates/view/' . (int)$r['local']['id']); ?>">
                        <?php echo h($r['name']); ?>
                    </a>
                    — <code><?php echo h($r['slug']); ?></code>
                    <?php if (!$r['local']['active']): ?>
                        <span style="color:#888; font-size:11px;">(<?php echo __('inactive'); ?>)</span>
                    <?php endif; ?>
                </li>
            <?php endforeach; ?>
        </ul>
        <p class="muted" style="font-size:12px;">
            <?php echo __('Rows whose upstream content has actually changed will be overwritten in place; identical content lands in <em>skipped_current</em> in the post-run summary.'); ?>
        </p>
    <?php endif; ?>

    <h3><?php echo __('Will skip (forked)'); ?> <span class="muted">(<?php echo count($buckets['forked']); ?>)</span></h3>
    <?php if (empty($buckets['forked'])): ?>
        <p><em><?php echo __('No forked rows.'); ?></em></p>
    <?php else: ?>
        <ul>
            <?php foreach ($buckets['forked'] as $r): ?>
                <li>
                    <a href="<?php echo h($baseurl . '/event_templates/view/' . (int)$r['local']['id']); ?>">
                        <?php echo h($r['name']); ?>
                    </a>
                    — <code><?php echo h($r['slug']); ?></code>
                </li>
            <?php endforeach; ?>
        </ul>
        <p class="muted" style="font-size:12px;">
            <?php echo __('Rows you have flipped to <code>misp_default = 0</code> are not touched. To re-opt-in to library updates, flip the flag back via the builder.'); ?>
        </p>
    <?php endif; ?>

    <?php
        echo $this->Form->create('EventTemplate', array(
            'url' => array('controller' => 'event_templates', 'action' => 'update'),
            'type' => 'post',
        ));
    ?>
        <button type="submit" class="btn btn-primary" style="margin-top:14px;">
            <i class="fa fa-sync"></i> <?php echo __('Apply update'); ?>
        </button>
        <a href="<?php echo h($baseurl . '/event_templates/index'); ?>" class="btn">
            <?php echo __('Cancel'); ?>
        </a>
    <?php echo $this->Form->end(); ?>
</div>
<?php
echo $this->element('/genericElements/SideMenu/side_menu', array(
    'menuList' => 'eventTemplates',
    'menuItem' => 'index',
));
?>
