<?php
/**
 * Status of the ai_connector module on the AI settings tab (legacy theme),
 * computed by Module::aiStatus() when the tab loads. Same content as the
 * Overmind card, in the diagnostics-box style of this theme.
 *
 * Params:
 *  - status  array from Module::aiStatus()
 */

$colours = array('green' => '#009933', 'orange' => '#e68a00', 'red' => '#cc0000', 'grey' => '#666666');
$span = function ($colour, $text) use ($colours) {
    return sprintf('<span style="color:%s;">%s</span>', $colours[$colour], h($text));
};

if (!$status['enabled']) {
    $verdict = $span('grey', __('Disabled'));
} elseif (!$status['reachable']) {
    $verdict = $span('red', __('Unreachable'));
} elseif (!$status['listed']) {
    $verdict = $span('orange', __('Module missing'));
} else {
    $verdict = $span('green', __('Ready'));
}
?>
<h3><?= __('Module status') ?>…<?= $verdict ?></h3>
<p><?= __('The ai_connector module as seen from this instance, checked when this tab loads.') ?></p>
<div class="diagnostics-box">
    <?= __('AI services') ?>…<?= $status['enabled'] ? $span('green', __('Enabled')) : $span('grey', __('Disabled')) ?>
    <?php if (!$status['enabled']): ?>
        <span style="color:<?= $colours['grey'] ?>;"><?= __('Set %s to true to check the module.', '<code>Plugin.AI_services_enable</code>') ?></span>
    <?php endif; ?>
    <br>
    <?= __('Module server') ?>…<code><?= h($status['server']) ?></code><br>
    <?php if ($status['enabled']): ?>
        <?= __('Reachable') ?>…<?= $status['reachable'] ? $span('green', __('OK')) : $span('red', $status['error']) ?><br>
    <?php endif; ?>
    <?php if ($status['reachable']): ?>
        <?php if ($status['listed']): ?>
            <?php
            $details = array();
            if (!empty($status['module']['version'])) {
                $details[] = __('version %s', $status['module']['version']);
            }
            if (!empty($status['module']['description'])) {
                $details[] = $status['module']['description'];
            }
            ?>
            ai_connector…<?= $span('green', __('Listed')) ?><?= $details ? ' ' . $span('grey', implode(' — ', $details)) : '' ?><br>
        <?php else: ?>
            ai_connector…<?= $span('orange', __('Not listed')) ?> <?= $span('grey', $status['error'] ?: __('The server answers, but does not offer the ai_connector module.')) ?><br>
        <?php endif; ?>
    <?php endif; ?>
</div>
