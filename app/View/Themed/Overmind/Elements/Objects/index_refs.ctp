<?php
/**
 * An object's reference counts in the objects indexes: outgoing, then incoming.
 *
 * Parameters:
 *   out    int
 *   in     int
 *   title  bool  name the two counts on hover (default true); off inside a
 *                control that has a hover text of its own
 */
$out = (int)($out ?? 0);
$in = (int)($in ?? 0);
$title = $title ?? true;
?>
<span class="oi-refs<?= $out + $in === 0 ? ' is-empty' : '' ?>"<?= $title
    ? ' title="' . h(__('%s outgoing, %s incoming references', $out, $in)) . '"' : '' ?>>
    <span><i class="fas fa-arrow-right"></i> <?= $out ?></span>
    <span><i class="fas fa-arrow-left"></i> <?= $in ?></span>
</span>
