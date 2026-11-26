<?php
/**
 * A galaxy cluster chip, built the way Badges/tag builds a tag chip: the
 * relationship the connector row carries joined on the left, then the value
 * itself. The colour comes from GalaxyColour keyed on the galaxy name - the
 * one source for a galaxy's colour, never a hash written here.
 *
 * Variables attendues :
 * - $cluster (array) ['value' => , 'galaxy' => , 'id' => ] (id optionnel)
 * - $local (bool)
 * Variables optionnelles :
 * - $relationship (string) type de relation (EventTag/AttributeTag.relationship_type)
 * - $hiddenClass  (string)
 * - $showGalaxy   (bool) libelle de la galaxie a droite de la pastille
 *                 (par defaut : oui des que la galaxie est connue)
 */

$value        = h($cluster['value'] ?? '');
$galaxy       = (string)($cluster['galaxy'] ?? '');
$hiddenClass  = $hiddenClass ?? '';
$relationship = !empty($relationship) ? trim((string)$relationship) : '';
$showGalaxy   = isset($showGalaxy) ? !empty($showGalaxy) : ($galaxy !== '');

$style = $this->GalaxyColour->badgeStyle($galaxy) . 'cursor:pointer;';
?>

<div class="d-inline-flex align-items-center me-1 mb-1">
    <?php if ($relationship !== ''): ?>
        <span class="badge text-white bg-dark <?= h($hiddenClass) ?>"
              style="border-radius:var(--bs-border-radius) 0 0 var(--bs-border-radius); font-size:.75rem;"
              title="<?= h(__('Cluster relationship: %s', $relationship)) ?>">
            <?= h($relationship) ?> :
        </span>
        <span class="badge <?= h($hiddenClass) ?>"
              style="<?= $style ?> border-radius:0 var(--bs-border-radius) var(--bs-border-radius) 0; font-size:.75rem;">
            <?php if (!empty($local)): ?>
                <i class="fas fa-user me-1" title="<?= __('Local cluster') ?>"></i>
            <?php endif; ?>
            <?= $value ?>
        </span>
    <?php else: ?>
        <span class="badge <?= h($hiddenClass) ?>" style="<?= $style ?> font-size:.75rem;">
            <?php if (!empty($local)): ?>
                <i class="fas fa-user me-1" title="<?= __('Local cluster') ?>"></i>
            <?php endif; ?>
            <?= $value ?>
        </span>
    <?php endif; ?>

    <?php if ($showGalaxy): ?>
        <span class="small text-muted ms-1" style="font-size:.7rem;"><?= h($galaxy) ?></span>
    <?php endif; ?>
</div>
