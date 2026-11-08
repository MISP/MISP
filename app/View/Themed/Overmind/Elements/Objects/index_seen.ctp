<?php
/**
 * An object's first and last seen days in the objects indexes, or a dash.
 *
 * Parameters:
 *   object  array  the row's Object
 */
$day = function ($value) {
    $dt = date_create((string)$value);
    return $dt === false ? (string)$value : $dt->format('Y-m-d');
};
$first = $object['first_seen'] ?? null;
$last = $object['last_seen'] ?? null;
if (empty($first) && empty($last)) {
    echo '<span class="oi-none">&mdash;</span>';
    return;
}
?>
<span class="oi-seen" title="<?= h(__('First seen %s, last seen %s', $first ?: '?', $last ?: '?')) ?>"><?=
    empty($first) ? '?' : h($day($first))
?><span class="oi-seen-dash">&ndash;</span><?= empty($last) ? '?' : h($day($last)) ?></span>
