<?php
/**
 * The animated MISP logo, for a loader that fills a panel, modal or page.
 * Small inline loaders (buttons, table cells) keep Bootstrap's spinner.
 *
 * @var string $size   '', 'sm' or 'lg'
 * @var string $label  Announced to assistive technology
 * @var string $class  Extra classes on the loader
 */
$classes = 'misp-loader';
if (!empty($size)) {
    $classes .= ' misp-loader-' . $size;
}
if (!empty($class)) {
    $classes .= ' ' . $class;
}
?>
<div class="<?= h($classes) ?>" role="status"><span class="visually-hidden"><?= h($label ?? __('Loading…')) ?></span></div>
