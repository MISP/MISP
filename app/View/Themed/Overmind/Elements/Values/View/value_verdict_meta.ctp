<?php
/**
 * The provenance of an assessment, on one quiet line under the reading:
 * the analyst profile it was computed under (and that it is not the
 * instance default, where it is not), when it was computed, the conflict
 * rule that decided the state where one did, and the Recompute and JSON
 * actions as icons.
 *
 * Shared by both verdict layouts. It says nothing about permissions: a
 * line volunteering that something might be missing would hint at records
 * the reader has no business knowing about.
 *
 * @var array $verdict
 * @var string $metaRule Optional, the rule that produced the state
 */
$metaRule = $metaRule ?? null;
$value = $valueIntelligence['value'] ?? null;
$computedAt = (int)$verdict['computed_at'];

$parts = array();
if (!empty($verdict['ledger'])) {
    $named = h($verdict['profile']);
    if (!empty($verdict['profile_id'])) {
        $named = $this->Html->link(
            $verdict['profile'],
            array(
                'controller' => 'analystProfiles',
                'action' => 'view',
                $verdict['profile_id'],
                '?' => $value === null ? array() : array('value' => $value),
            )
        );
    }
    $parts[] = h(__('Profile')) . ' ' . $named;
    if (isset($verdict['profile_is_instance_default']) && $verdict['profile_is_instance_default'] === false) {
        $parts[] = '<span title="' . h(__('A colleague using the default profile may see a different assessment.')) . '">'
            . h(__('not the default profile')) . '</span>';
    }
}
$parts[] = '<span title="' . h(sprintf(
    __('Computed at render, %s. Not stored, not synchronised.'),
    date('Y-m-d H:i:s', $computedAt)
)) . '">' . h(sprintf(
    date('Y-m-d', $computedAt) === date('Y-m-d') ? __('computed today %s') : __('computed %s'),
    date('Y-m-d', $computedAt) === date('Y-m-d') ? date('H:i', $computedAt) : date('Y-m-d H:i', $computedAt)
)) . '</span>';
if ($metaRule !== null) {
    $parts[] = h(__('conflict rule:')) . ' <em>' . h($metaRule) . '</em>';
}
?>
<div class="vp-verdict-meta">
    <span class="vp-verdict-meta-parts"><?= implode('<span class="vp-meta-sep">·</span>', $parts) ?></span>
    <?= $this->element('Values/View/value_verdict_actions') ?>
</div>
