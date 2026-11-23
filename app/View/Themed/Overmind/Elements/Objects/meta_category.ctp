<?php
/**
 * An object's meta-category: an icon of its own and a readable label. Drawn
 * before the name by Objects/object_header and by the add form's review.
 *
 * Parameters:
 *   meta  string  the object's or the template's meta-category
 */
$meta = (string)($meta ?? '');
if ($meta === '') {
    return;
}
$icons = [
    'climate' => 'fa-cloud-sun-rain',
    'detection' => 'fa-shield-halved',
    'file' => 'fa-file',
    'financial' => 'fa-building-columns',
    'followthemoney' => 'fa-money-bill-transfer',
    'health' => 'fa-heart-pulse',
    'internal' => 'fa-gear',
    'iot' => 'fa-microchip',
    'marine' => 'fa-anchor',
    'misc' => 'fa-shapes',
    'mobile' => 'fa-mobile-screen-button',
    'network' => 'fa-network-wired',
    'threat-hunting' => 'fa-crosshairs',
    'transport' => 'fa-truck',
    'vulnerability' => 'fa-bug',
];
$labels = [
    'followthemoney' => 'Follow the money',
    'iot' => 'IoT',
];
$label = $labels[$meta] ?? ucfirst(str_replace(['-', '_'], ' ', $meta));
?>
<span class="ov-obj-family" title="<?= h(__('Meta-category: %s', $meta)) ?>">
    <i class="fas <?= h($icons[$meta] ?? 'fa-cube') ?>" aria-hidden="true"></i>
    <span class="ov-obj-family-label"><?= h($label) ?></span>
</span>
