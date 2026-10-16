<?php
/**
 * One shape, drawn full, under its name.
 *
 * Two surfaces draw this and they must draw it identically: the pane a
 * run fills, and the pane a module's row opens onto before anybody has
 * pressed anything. Both are the same module's answer through the same
 * renderer, so the frame around it lives here rather than twice.
 *
 * The head names the shape and not the module: which module answered
 * is what the rail and the pane's own heading already say, and a
 * widget repeating it would be the third place on one screen.
 *
 * A plain partial, not an endpoint.
 *
 * @var array $shape One entry from `ValueRendererTool::drawFor`
 */
if ($shape['full'] === null) {
    return;
}
?>
<div class="vp-e-shape" data-vp-e-shape="<?= h($shape['shape']) ?>">
    <div class="vp-e-shape-head">
        <span class="vp-e-shape-name"><?= h(ucfirst(
            str_replace('-', ' ', $shape['shape'])
        )) ?></span>
        <span class="vp-e-shape-sub"><?=
            h($shape['description']) ?></span>
    </div>
    <?= $this->element($shape['full'], array(
        'data' => $shape['data'],
    )) ?>
</div>
