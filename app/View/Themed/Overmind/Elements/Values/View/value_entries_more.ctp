<?php
/**
 * The button under a Collaboration rail card's entries that unfolds the
 * ones past the first $fold (value-intelligence.js, [data-vp-entries-more]).
 *
 * @var int $count all the entries
 * @var int $fold how many show folded
 */
if ($count <= $fold) {
    return;
}
$hidden = $count - $fold;
?>
<button type="button" class="vp-entries-more" data-vp-entries-more>
    <?= h(sprintf(__n('Show %s more', 'Show %s more', $hidden), number_format($hidden))) ?>
    <i class="fas fa-chevron-down" aria-hidden="true"></i>
</button>
