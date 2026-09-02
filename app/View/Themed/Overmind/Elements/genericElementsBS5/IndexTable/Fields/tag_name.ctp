<?php
$tag = Hash::extract($row, $field['data_path']);

if (empty($tag)) {
    return;
}

$showFavourite = false;
if (empty($row['tag'])) {
    $showFavourite = true;
}

echo $this->element('genericElementsBS5/Badges/tag', [
        'tag' => $tag,
        'local' => $tag['local_only'] ?? false,
        'hiddenClass' => null,
        'showFavourite' => $showFavourite
    ]);

$taxonomy = Hash::extract($row, $field['data_path'] . '.Taxonomy');

if (empty($taxonomy) || empty($taxonomy['namespace'])) {
    return;
}

$namespace = h($taxonomy['namespace']);
$canViewTaxonomy = !empty($taxonomy['id']) && $this->Acl->canAccess('taxonomies', 'view');
?>

<div class="ms-4 mt-1">
    <?php if ($canViewTaxonomy): ?>
        <a class="text-primary text-decoration-none d-flex align-items-center small "
            href="<?= $baseurl ?>/taxonomies/view/<?= (int)$taxonomy['id'] ?>"
            title="<?= __('View the %s taxonomy', $namespace) ?>"
            aria-label="<?= __('View the %s taxonomy', $namespace) ?>">
            <span class="misp-icon misp-icon-taxonomy misp-simple me-1"></span>
            <?= $namespace ?>
        </a>
    <?php else: ?>
        <p class="text-reset text-decoration-none d-flex align-items-center small "
            href="<?= $baseurl ?>/taxonomies/view/<?= (int)$taxonomy['id'] ?>">
            <span class="misp-icon misp-icon-taxonomy misp-simple me-1"></span>
            <?= $namespace ?>
        </p>
    <?php endif; ?>
</div>