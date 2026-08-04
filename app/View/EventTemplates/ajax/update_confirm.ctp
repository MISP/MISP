<?php
/*
 * Popover-friendly confirm form for /event_templates/update (GET).
 * Rendered without a layout into #popover_form. Yes posts to the
 * same URL to execute the run; No closes via cancelPrompt().
 *
 * `$preview` shape matches `library_status` (PRD §5.3).
 */
$present = isset($preview['present_in_library']) ? $preview['present_in_library'] : array();
$failed = isset($preview['failed']) ? $preview['failed'] : array();

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
$renderBucket = function ($rows, $emptyText) {
    if (empty($rows)) {
        echo '<p style="margin:4px 0; color:#888; font-style:italic;">' . h($emptyText) . '</p>';
        return;
    }
    echo '<ul style="margin:4px 0 4px 20px;">';
    foreach ($rows as $r) {
        echo '<li><code>' . h($r['slug'] ?? '') . '</code> — ' . h($r['name'] ?? '') . '</li>';
    }
    echo '</ul>';
};
?>
<div class="confirmation">
    <legend><?php echo __('Update event templates from library'); ?></legend>
    <div style="padding:5px 10px 8px 10px;">
        <p style="margin-bottom:8px;">
            <?php echo __('Reconcile the bundled <code>misp-event-templates</code> submodule with the local <code>event_templates</code> table.'); ?>
        </p>

        <?php if (!empty($failed)): ?>
            <div class="alert alert-error" style="margin-bottom:8px;">
                <strong><?php echo __('%d on-disk template(s) could not be parsed:', count($failed)); ?></strong>
                <ul style="margin:4px 0 0 20px;">
                    <?php foreach ($failed as $f): ?>
                        <li><code><?php echo h($f['slug'] ?? '(no slug)'); ?></code> — <?php echo h($f['error']); ?></li>
                    <?php endforeach; ?>
                </ul>
            </div>
        <?php endif; ?>

        <h4 style="margin:8px 0 0 0;">
            <?php echo __('Will install'); ?>
            <span style="color:#888; font-weight:normal;">(<?php echo count($buckets['install']); ?>)</span>
        </h4>
        <?php $renderBucket($buckets['install'], __('Nothing to install — every library template already exists locally.')); ?>

        <h4 style="margin:8px 0 0 0;">
            <?php echo __('May update'); ?>
            <span style="color:#888; font-weight:normal;">(<?php echo count($buckets['managed']); ?>)</span>
        </h4>
        <?php $renderBucket($buckets['managed'], __('No library-managed rows installed yet.')); ?>

        <h4 style="margin:8px 0 0 0;">
            <?php echo __('Will skip (forked)'); ?>
            <span style="color:#888; font-weight:normal;">(<?php echo count($buckets['forked']); ?>)</span>
        </h4>
        <?php $renderBucket($buckets['forked'], __('No forked rows.')); ?>

        <table style="margin-top:10px;">
            <tr>
                <td style="vertical-align:top">
                    <button type="button" id="PromptYesButton"
                            class="btn btn-primary"
                            onclick="submitEventTemplatesLibraryUpdate()"
                            aria-label="<?php echo __('Update'); ?>"
                            title="<?php echo __('Update'); ?>">
                        <?php echo __('Update'); ?>
                    </button>
                </td>
                <td style="width:540px;"></td>
                <td style="vertical-align:top;">
                    <span role="button" tabindex="0"
                          class="btn btn-inverse"
                          id="PromptNoButton"
                          onclick="cancelPrompt()"
                          aria-label="<?php echo __('Cancel'); ?>"
                          title="<?php echo __('Cancel'); ?>">
                        <?php echo __('Cancel'); ?>
                    </span>
                </td>
            </tr>
        </table>
    </div>
</div>
