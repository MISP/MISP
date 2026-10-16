<?php
/**
 * One tag as a chip.
 * - $tag (array) flat tag: name, colour, id, numerical_value, favourite
 * - $local (bool)
 * - $hiddenClass (string)
 * - $showFavourite (bool) optional
 * - $relationship (string) optional, EventTag/AttributeTag.relationship_type
 * - $searchUrl (string) optional link prefix, no link by default
 * - $inline (bool) optional, path and value on one row
 */
$showFavourite = $showFavourite ?? false;
$chip = $this->TagChip->chip([
    'Tag' => $tag,
    'local' => !empty($local),
    'relationship_type' => !empty($relationship) ? trim((string)$relationship) : null,
], [
    'searchUrl' => $searchUrl ?? '',
    'class' => $hiddenClass ?? '',
    'inline' => !empty($inline),
]);
if ($showFavourite && !empty($tag['id'])): ?>
<span class="d-inline-flex align-items-center <?= h($hiddenClass ?? '') ?>">
    <i
        class="<?= !empty($tag['favourite']) ? 'fas fa-star' : 'far fa-star' ?> text-warning me-1 tag-star"
        data-id="<?= (int)$tag['id'] ?>"
        data-name="<?= h($tag['name'] ?? '') ?>"
        style="cursor:pointer;"
    ></i>
    <?= $chip ?>
</span>
<?php else: ?>
<?= $chip ?>
<?php endif; ?>
