<?php
/*
 * cluster_relations.ctp
 *
 * Expected:
 * $data_path => path to the GalaxyCluster array (holding event_count / attribute_count)
 */
$cluster = Hash::get($row, $field['data_path']) ?? [];
$ev = (int)($cluster['event_count'] ?? 0);
$at = (int)($cluster['attribute_count'] ?? 0);
?>

<div class="d-flex flex-column flex-wrap gap-1">
    <div class="d-inline-flex align-items-center fw-bold text-nowrap text-event">
        <span class="misp-icon misp-icon-event misp-simple misp-icon-md me-1"></span>
        <span><?= h($ev) ?> <?= $ev > 1 ? __('Events') : __('Event') ?></span>
    </div>
    <div class="d-inline-flex align-items-center fw-bold text-nowrap text-attribute">
        <span class="misp-icon misp-icon-attribute misp-simple misp-icon-md me-1"></span>
        <span><?= h($at) ?> <?= $at > 1 ? __('Attributes') : __('Attribute') ?></span>
    </div>
</div>
