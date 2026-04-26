<?php
$data = Hash::extract($row, $field['data_path']);

if (empty($data)) {
    return;
}

$maxVisible = 4;
$totalTags = count($data);
$hiddenCount = max(0, $totalTags - $maxVisible);

?>

<div class="tag-container d-inline-flex flex-wrap align-items-center">

<?php
$visibleIndex = 0;

foreach ($data as $tagWrapper) {
    if (empty($tagWrapper['Tag'])) {
        continue;
    }

    $hiddenClass = ($visibleIndex >= $maxVisible) ? 'd-none extra-tag' : '';

    echo $this->element('genericElementsBS5/Badges/tag', [
        'tag' => $tagWrapper['Tag'],
        'local' => $tagWrapper['local'] ?? false,
        'hiddenClass' => $hiddenClass,
        'showFavourite' => false
    ]);

    $visibleIndex++;
}
?>

<?php if ($hiddenCount > 0): ?>
    <span
        class="badge bg-secondary text-white me-1 mb-1 tag-expand"
        style="cursor:pointer;"
        onclick="toggleTags(this)"
    >
        +<?= $hiddenCount ?>
    </span>
<?php endif; ?>

</div>
