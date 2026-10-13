<?php
/**
 * The types the rail is matched on, where each came from, as one control:
 * `ip-dst, ip-src` read from the value ⌄. It opens the type menu.
 *
 * A type the organisation already asked a module about says so, whether
 * it was read, picked or is only there because of that earlier answer.
 *
 * @var array $typeView Built by value_enrichment.ctp
 */
$lead = $typeView['lead'];
$kept = $typeView['kept'];
$basis = $typeView['source'] === 'picked'
    ? __('picked by you')
    : __('read from the value');
$askedBefore = __('asked before');
$leadKept = count($lead) === 1 && in_array($lead[0], $kept, true);

$segments = array();
$labels = array();
if (!empty($lead)) {
    $names = array();
    foreach ($lead as $type) {
        $names[] = '<span class="vp-et-chip-type">' . h($type) . '</span>';
    }
    $said = $basis . ($leadKept ? ', ' . $askedBefore : '');
    $segments[] = '<span class="vp-et-chip-seg">'
        . '<span class="vp-et-chip-types">'
        . implode('<span class="vp-et-chip-comma">,</span>', $names)
        . '</span><span class="vp-et-chip-basis">' . h($said) . '</span>'
        . '</span>';
    $labels[] = implode(', ', $lead) . ', ' . $said;
}
$alsoKept = count($lead) > 1 ? array_intersect($lead, $kept) : array();
foreach (array_unique(array_merge($typeView['held'], $alsoKept)) as $type) {
    $segments[] = '<span class="vp-et-chip-seg"><span class="vp-et-chip-type">'
        . h($type) . '</span><span class="vp-et-chip-basis">'
        . h($askedBefore) . '</span></span>';
    $labels[] = $type . ', ' . $askedBefore;
}
$warn = !empty($typeView['failing']);
?>
<button type="button"
        class="vp-et-chip<?= $warn ? ' vp-et-chip-warn' : '' ?>"
        data-vp-et-chip
        aria-haspopup="dialog" aria-expanded="false"
        aria-controls="<?= h($typeView['uid']) ?>-pop"
        title="<?= h(__('Change the type modules are matched on')) ?>"
        aria-label="<?= h(sprintf(
            __('Modules are matched on %s. Change the type'),
            implode('; ', $labels)
        )) ?>"
        data-vp-et-switching="<?= h(__('switching…')) ?>">
    <?php if ($warn): ?>
        <i class="fas fa-triangle-exclamation vp-et-chip-warnico"
           aria-hidden="true"></i>
    <?php endif; ?>
    <?= implode(
        '<span class="vp-et-chip-sep" aria-hidden="true"></span>',
        $segments
    ) ?>
    <i class="fas fa-chevron-down vp-et-chip-chev" aria-hidden="true"></i>
</button><?= $this->element('Values/View/value_enrichment_type_picker', array(
    'typeView' => $typeView,
    'inline' => false,
)) ?>
