<?php
/**
 * Variables attendues :
 * - $tag (array)
 * - $local (bool)
 * - $hiddenClass (string)
 * - $showStar (bool) (optionnel)
 */

$showFavourite = $showFavourite ?? false;
$name = h($tag['name']);
$isFavourite = !empty($tag['favourite']);

// Not every association fetches the colour (tag collections, for one).
$colour = !empty($tag['colour']) ? $tag['colour'] : '#0088cc';

$bgColor = 'background-color:' . h($colour);
$textColor = $this->TextColour->getTextColour($colour);
$shadow = 'filter: drop-shadow(-1px 3px 2px rgba(50, 50, 0, 0.5))';
$metallicEffect = "background-image: linear-gradient(145deg, rgba(255,255,255,0.25) 0%, rgba(255,255,255,0.05) 40%, rgba(0,0,0,0.05) 100%)";
$text = "text-align:left; white-space:normal; word-wrap:break-word";

$style = sprintf('%s; color: %s; %s; %s; %s; cursor:pointer;', $bgColor, $textColor, $shadow, $metallicEffect, $text);

// if ($local) {
//     $style .= sprintf(' border:2px dashed %s', $textColor);
// }
?>

<div class="d-inline-flex align-items-center">
    <?php if ($showFavourite && !empty($tag['id'])): ?>
        <i
            class="<?= $isFavourite ? 'fas fa-star' : 'far fa-star' ?> text-warning me-1 tag-star"
            data-id="<?= (int)$tag['id'] ?>"
            style="cursor:pointer;"
        ></i>
    <?php endif; ?>

    <span class="badge me-1 mb-1 <?= h($hiddenClass) ?>" style="<?= $style ?>">
        <?php if ($local): ?>
            <i class="fas fa-user me-1"></i>
        <?php endif; ?>

        <?= $name ?>
    </span>
</div>