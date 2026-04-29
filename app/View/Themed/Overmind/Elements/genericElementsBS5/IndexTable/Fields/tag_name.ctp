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

$taxonomy = Hash::extract($row, 'Tag.Taxonomy.namespace');

if (empty($taxonomy)) {
    return;
}

echo $this->element(
    'genericElementsBS5/Badges/links',
    [
        'links' => $taxonomy,
        'object' => $field,
        'row' => $row
    ]
);

?>