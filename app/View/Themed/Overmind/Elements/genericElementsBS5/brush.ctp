<?php
/**
 * The layer misp-brush.js drags a range over. Place it inside the
 * `position: relative` box that holds the chart, and load misp-brush.js
 * and misp-brush.css on the page.
 *
 * @var bool $hidden Render hidden, for a caller that reveals it once its
 *     script has wired it
 */
?>
<div class="misp-brush" data-misp-brush<?= empty($hidden) ? '' : ' hidden' ?>>
    <div class="misp-brush-mask" data-misp-brush-mask-left></div>
    <div class="misp-brush-window" data-misp-brush-handle></div>
    <div class="misp-brush-mask" data-misp-brush-mask-right></div>
</div>
